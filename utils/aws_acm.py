from datetime import datetime, timedelta
from deepdiff import DeepDiff
import glueops.aws
import utils.vault
import glueops.certificates
import glueops.setup_logging
import os
import utils.aws_rate_limiter
import utils.RedisCache
import pickle

REDIS_CONNECTION = os.environ.get('REDIS_CONNECTION_STRING', 'redis://glueops-operator-shared-redis.glueops-core-operators.svc.cluster.local:6379')
CACHE_TTL = os.environ.get('CACHE_TTL', '1')
MAX_TTL_ORPHANED_CERTS = os.environ.get('MAX_TTL_ORPHANED_CERTS', '172800') #ACM Times out after 72 hours. This is set to 48 hours.

logger = glueops.setup_logging.configure(level=os.environ.get('LOG_LEVEL', 'WARNING'))
redis_client = utils.RedisCache.RedisCache(redis_url=REDIS_CONNECTION)
limiter = utils.aws_rate_limiter.RateLimiterUtil(REDIS_CONNECTION)

def is_certificate_used(cert_state):
    certificate_details = cert_state['Certificate']
    usages = certificate_details['InUseBy']
    if len(usages) > 0:
        logger.debug(f"{certificate_details['CertificateArn']} is in use by: {usages}")
        return True
    else:
        logger.debug(f"{certificate_details['CertificateArn']} is not used by anything yet: {usages}")
        return False


def get_cert_state(certificate_arn):
    certificate = describe_certificate(certificate_arn=certificate_arn)
    return certificate


def is_cert_is_old(cert_state):
    created_date = cert_state['Certificate']['CreatedAt']
    minutes = round(MAX_TTL_ORPHANED_CERTS / 60) 

    # Ensure current time and created_date are in the same timezone
    current_time = datetime.now(created_date.tzinfo)
    duration_since_creation = current_time - created_date

    # Check if the certificate is older than 'minutes'
    arn = cert_state['Certificate']['CertificateArn']
    old_certificate = duration_since_creation > timedelta(minutes=minutes)

    if old_certificate:
        logger.info(f"ACM ARN: {arn} appears old. It was created on {created_date} more than {minutes} minutes ago")
    else:
        logger.info(f"ACM ARN: {arn} appears new. It was {created_date} less than {minutes} minutes ago")
        
    return old_certificate



def is_cert_imported(certificate_arn):
    certificate = describe_certificate(certificate_arn=certificate_arn)
    return str(certificate['Certificate']['Type']).lower() == str('IMPORTED').lower()


def cleanup_orphaned_certs(aws_resource_tags):
    existing_cert_arns = glueops.aws.get_resource_arns_using_tags(
        aws_resource_tags, ['acm:certificate'])
    for existing_cert_arn in existing_cert_arns:
        cert_state = get_cert_state(existing_cert_arn)
        if is_certificate_used(cert_state):
            logger.info(
                f"Leaving ACM ARN {existing_cert_arn} alone as it's in use.")
        else:
            if is_cert_is_old(cert_state):
                logger.info(f"Deleting: {existing_cert_arn} Reason: Cert is not actively used or is old/expired")
                delete_acm_certificate(existing_cert_arn)


def create_acm_certificate(domains, name_hashed, aws_resource_tags):
    logger.info(
        f"Creating ACM certificate for: {domains} with tags: {aws_resource_tags}")
    if not domains:
        raise ValueError("At least one domain is required")
    
    main_domain = domains[0]
    alternative_names = domains[1:]
    
    existing_arn = find_certificate_by_domain(aws_resource_tags=aws_resource_tags, domain=main_domain,sans=alternative_names)
    if existing_arn is None:
        acm = glueops.aws.create_aws_client('acm')

        # Prepare common request parameters
        request_params = {
            'DomainName': main_domain,
            'ValidationMethod': 'DNS',
            'IdempotencyToken': name_hashed,
            'Tags': aws_resource_tags
        }

        # If there are alternative names, add them to the request parameters
        if alternative_names:
            request_params['SubjectAlternativeNames'] = alternative_names
        limiter.allow_request_aws_acm_request_certificate()
        response = acm.request_certificate(**request_params)

        certificate_arn = response['CertificateArn']
        logger.info(
            f"Created ACM certificate for: {domains} and got ARN: {certificate_arn}")
        return certificate_arn
    else:
        logger.info(f"Found existing certificate that can be used: {existing_arn}")
        return existing_arn

def find_certificate_by_domain(aws_resource_tags, domain, sans=None):
    logger.info(f"Searching for existing certificate with tags: {aws_resource_tags}")
    existing_acm_arns = glueops.aws.get_resource_arns_using_tags(
        aws_resource_tags, ['acm:certificate'])

    for arn in existing_acm_arns:
        response = describe_certificate(certificate_arn=arn)
        cert_details = response.get('Certificate', {})
        cert_domain = cert_details.get('DomainName')
        cert_sans = cert_details.get('SubjectAlternativeNames', [])
        cert_status = cert_details.get('Status')
        if cert_status in [ 'PENDING_VALIDATION','ISSUED']:
            if domain == cert_domain:
                if sans:
                    if all(san in cert_sans for san in sans):
                        return arn
                else:
                    logger.info(f"Found existing certificate {arn} with tags: {aws_resource_tags}")
                    return arn
    logger.info(f"No usable certificates found with tags: {aws_resource_tags}")
    return None

def check_certificate_validation(certificate_arn):
    logger.info(f"Checking on ACM Certificate: {certificate_arn}")
    cert_details =  describe_certificate(certificate_arn=certificate_arn)['Certificate']
    # Check for expiration
    if "NotAfter" in cert_details:
        expiration_date_naive = cert_details['NotAfter'].replace(tzinfo=None)
        if expiration_date_naive - timedelta(days=45) <= datetime.utcnow():
            overall_health = "NotHealthy"
        else:
            overall_health = "Healthy"

    # Check for status
    not_healthy_statuses = [
        "PENDING_VALIDATION",
        "REVOKED",
        "EXPIRED",
        "FAILED",
        "VALIDATION_TIMED_OUT",
        "RENEWING"
    ]
    if cert_details.get('Status') in not_healthy_statuses:
        overall_health = "NotHealthy"

    return {
        "arn": certificate_arn,
        "status": cert_details.get('Status'),
        "validations": cert_details.get('DomainValidationOptions'),
        "expiration_date": str(cert_details.get('NotAfter')),
        "Health": overall_health
    }


def delete_acm_certificate(certificate_arn):
    logger.info(f"Deleting ACM Certificate {certificate_arn}")
    acm = glueops.aws.create_aws_client('acm')
    acm.delete_certificate(CertificateArn=certificate_arn)


def delete_all_acm_certificates(aws_resource_tags):
    logger.info(
        f"Deleting all ACM Certificates with these tags: {aws_resource_tags}")
    arns_to_delete = glueops.aws.get_resource_arns_using_tags(
        aws_resource_tags, ['acm:certificate'])

    for arn in arns_to_delete:
        delete_acm_certificate(arn)

    if arns_to_delete:
        logger.info(
            f"Still deleting all ACM Certificates with these tags: {aws_resource_tags}")
        return False
    else:
        logger.info(
            f"Finished deleting all ACM Certificates with these tags: {aws_resource_tags}")
        return True


def get_domains_from_existing_certificate(certificate_arn):
    logger.info(
        f"Get domains from existing ACM certificate: {certificate_arn}")
    response =  describe_certificate(certificate_arn=certificate_arn)
    domain_validations = response.get(
        'Certificate', {}).get('DomainValidationOptions', [])
    acm_domains = {validation.get('DomainName')
                   for validation in domain_validations}
    return acm_domains


def need_new_certificate(certificate_arn, domains):
    existing = get_domains_from_existing_certificate(certificate_arn)
    diff = DeepDiff(set(existing), set(domains), ignore_order=True)
    if diff:
        logger.info(f"Differences between old and new ACM certificate: {diff}")
        return True
    else:
        return False


def does_acm_cert_exist(certificate_arn):
    logger.info("Checking to see if certificate exists or not")
    try:
        get_domains_from_existing_certificate(certificate_arn)
    except Exception as e:
        logger.error(
            f"While checking to see if the acm certificate: {certificate_arn} exists the following error returned: {e}")
        return False
    return True


def get_cert_from_vault(secret_path):
    response = utils.vault.get_data_from_vault(secret_path)

    certificate = response.get('CERTIFICATE')
    private_key = response.get('PRIVATE_KEY')
    certificate_chain = response.get('CERTIFICATE_CHAIN')

    # Check if any value is None and raise an exception
    if None in [certificate, private_key, certificate_chain]:
        raise ValueError(
            "One or more values are missing from the response: CERTIFICATE, PRIVATE_KEY, CERTIFICATE_CHAIN")

    return certificate, private_key, certificate_chain


def get_serial_number(certificate_arn):
    certificate = describe_certificate(certificate_arn=certificate_arn)
    return certificate['Certificate']['Serial']


def import_cert_to_acm(secret_path_in_vault, aws_resource_tags):
    certificate, private_key, certificate_chain = get_cert_from_vault(
        secret_path_in_vault)
    cert_serial_number = glueops.certificates.extract_serial_number_from_cert_string(
        certificate).lower()

    existing_cert_arns = glueops.aws.get_resource_arns_using_tags(
        aws_resource_tags, ['acm:certificate'])

    for cert_arn in existing_cert_arns:
        if cert_serial_number == get_serial_number(cert_arn).lower():
            logger.info(
                f"Certificate from Vault {secret_path_in_vault} already in AWS ACM as: {cert_arn}")
            return cert_arn

    logger.info(
        f"Certificate from Vault {secret_path_in_vault} is not in AWS ACM. Importing...")

    acm = glueops.aws.create_aws_client('acm')
    response = acm.import_certificate(
        Certificate=certificate,
        PrivateKey=private_key,
        CertificateChain=certificate_chain,
        Tags=aws_resource_tags
    )

    return response['CertificateArn']


def describe_certificate(certificate_arn):
    """Get the certificate details, with caching."""
    # Try to get the cached data
    
    cached_data = redis_client.get(certificate_arn)
    if cached_data:
        logger.debug(f"Retrieved {certificate_arn} from cache")
        return pickle.loads(cached_data)
    
    # If not cached, fetch data from ACM
    acm = glueops.aws.create_aws_client('acm')
    limiter.allow_request_aws_acm_describe_certificate()
    certificate_details = acm.describe_certificate(CertificateArn=certificate_arn)
    
    
    # Cache the result with a TTL
    redis_client.set(certificate_arn, pickle.dumps(certificate_details), ttl=CACHE_TTL)
    logger.debug(f"Retrieved {certificate_arn} from ACM and cached with TTL: {CACHE_TTL}")
    return certificate_details