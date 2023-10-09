from datetime import datetime, timedelta
from deepdiff import DeepDiff
from glueops.aws import *
from utils.vault import *
import glueops.logging
import glueops.certificates


logger = glueops.logging.configure()


def is_certificate_used(cert_state):
    return cert_state['Certificate']['InUseBy']

def get_cert_state(certificate_arn):
    acm = create_aws_client('acm')
    certificate = acm.describe_certificate(CertificateArn=certificate_arn)
    return certificate


def is_cert_is_old(cert_state):
    created_date = cert_state['Certificate']['CreatedAt']
    minutes = 43800
    # Check if the certificate is older than 'minutes'
    arn = cert_state['Certificate']['CertificateArn']
    logger.info(f"Certificate ACM ARN: {arn} was created on: {created_date}")
    old_certificate = (datetime.now(created_date.tzinfo) - created_date) > timedelta(minutes=minutes)
    logger.info(f"ACM ARN: {arn} was created more than {minutes} minutes ago: {old_certificate}")
    return old_certificate


def is_cert_imported(certificate_arn):
    acm = create_aws_client('acm')
    certificate = acm.describe_certificate(CertificateArn=certificate_arn)
    return str(certificate['Certificate']['Type']).lower() == str('IMPORTED').lower()


def cleanup_orphaned_certs(aws_resource_tags):
    existing_cert_arns = get_resource_arns_using_tags(aws_resource_tags, ['acm:certificate'])
    for existing_cert_arn in existing_cert_arns:
        cert_state = get_cert_state(existing_cert_arn)
        if is_certificate_used(cert_state):
            logger.info(f"Leaving ACM ARN {existing_cert_arn} alone as it's in use.")
        else:
            if is_cert_is_old(cert_state):
                delete_acm_certificate(existing_cert_arn)


def create_acm_certificate(domains, name, aws_resource_tags):
    logger.info(f"Creating ACM certificate for: {domains} with tags: {aws_resource_tags}")
    if not domains:
        raise ValueError("At least one domain is required")

    main_domain = domains[0]
    alternative_names = domains[1:]
    
    acm = create_aws_client('acm')

    # Prepare common request parameters
    request_params = {
        'DomainName': main_domain,
        'ValidationMethod': 'DNS',
        'IdempotencyToken': name,
        'Tags': aws_resource_tags
    }

    # If there are alternative names, add them to the request parameters
    if alternative_names:
        request_params['SubjectAlternativeNames'] = alternative_names

    response = acm.request_certificate(**request_params)
    
    certificate_arn = response['CertificateArn']
    logger.info(f"Created ACM certificate for: {domains} and got ARN: {certificate_arn}")

    return certificate_arn


def check_certificate_validation(certificate_arn):
    logger.info(f"Checking on ACM Certificate: {certificate_arn}")
    acm = create_aws_client('acm')
    cert_details = acm.describe_certificate(CertificateArn=certificate_arn)['Certificate']
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
    acm = create_aws_client('acm')
    acm.delete_certificate(CertificateArn=certificate_arn)
    
    
def delete_all_acm_certificates(aws_resource_tags):
    logger.info(f"Deleting all ACM Certificates with these tags: {aws_resource_tags}")
    arns_to_delete = get_resource_arns_using_tags(aws_resource_tags, ['acm:certificate'])
    
    for arn in arns_to_delete:
        delete_acm_certificate(arn)

    if arns_to_delete:
        logger.info(f"Still deleting all ACM Certificates with these tags: {aws_resource_tags}")
        return False
    else:
        logger.info(f"Finished deleting all ACM Certificates with these tags: {aws_resource_tags}")
        return True


        
        


def get_domains_from_existing_certificate(certificate_arn):
    logger.info(
        f"Get domains from existing ACM certificate: {certificate_arn}")
    acm = create_aws_client('acm')
    response = acm.describe_certificate(
        CertificateArn=certificate_arn
    )
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
        logger.error(f"While checking to see if the acm certificate: {certificate_arn} exists the following error returned: {e}")
        return False
    return True


def get_cert_from_vault(secret_path):
    response = get_data_from_vault(secret_path)
    
    certificate = response.get('CERTIFICATE')
    private_key = response.get('PRIVATE_KEY')
    certificate_chain = response.get('CERTIFICATE_CHAIN')
        
    # Check if any value is None and raise an exception
    if None in [certificate, private_key, certificate_chain]:
        raise ValueError("One or more values are missing from the response: CERTIFICATE, PRIVATE_KEY, CERTIFICATE_CHAIN")

        
    return certificate, private_key, certificate_chain


def get_serial_number(certificate_arn):
    acm = create_aws_client('acm')
    certificate = acm.describe_certificate(CertificateArn=certificate_arn)
    return certificate['Certificate']['Serial']

def import_cert_to_acm(secret_path_in_vault, aws_resource_tags):
    certificate, private_key, certificate_chain = get_cert_from_vault(secret_path_in_vault)
    cert_serial_number = glueops.certificates.extract_serial_number_from_cert_string(certificate).lower()

    existing_cert_arns = get_resource_arns_using_tags(aws_resource_tags, ['acm:certificate'])

    for cert_arn in existing_cert_arns:
        if cert_serial_number == get_serial_number(cert_arn).lower():
            logger.info(f"Certificate from Vault {secret_path_in_vault} already in AWS ACM as: {cert_arn}")
            return cert_arn

    logger.info(f"Certificate from Vault {secret_path_in_vault} is not in AWS ACM. Importing...")
    
    acm = create_aws_client('acm')
    response = acm.import_certificate(
        Certificate=certificate,
        PrivateKey=private_key,
        CertificateChain=certificate_chain,
        Tags=aws_resource_tags
    )
    
    return response['CertificateArn']
