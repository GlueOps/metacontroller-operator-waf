import boto3
import time
from datetime import datetime, timezone, timedelta
from deepdiff import DeepDiff

from json_log_formatter import JsonFormatter
import logging
logger = logging.getLogger('GLUEOPS_WAF_OPERATOR')
from utils.tools import *
from utils.vault import *


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


def create_acm_certificate(domains, uid, aws_resource_tags):
    logging.info(f"Creating ACM certificate for: {domains} with tags: {aws_resource_tags}")
    if not domains:
        raise ValueError("At least one domain is required")

    main_domain = domains[0]

    alternative_names = domains[1:]

    # change the region as needed
    acm = create_aws_client('acm')
    response = None
    uid = str(uid)[:-10].replace('-','')

    try:
        if len(alternative_names) == 0:
            response = acm.request_certificate(
                DomainName=main_domain,
                ValidationMethod='DNS',  # this example is for DNS validation
                # this should be a unique string value. This can be anything as long as it's the same per unique request. But probably just best to leave it hardcoded to glueops. If the same certificate gets requested in the same hour it'll help avoid duplicates
                IdempotencyToken=uid,
                Tags=aws_resource_tags
            )
        else:
            response = acm.request_certificate(
                DomainName=main_domain,
                ValidationMethod='DNS',  # this example is for DNS validation
                SubjectAlternativeNames=alternative_names,
                # this should be a unique string value. This can be anything as long as it's the same per unique request. But probably just best to leave it hardcoded to glueops. If the same certificate gets requested in the same hour it'll help avoid duplicates
                IdempotencyToken=uid,
                Tags=aws_resource_tags
            )
        certificate_arn = response['CertificateArn']
        logging.info(
            f"Created ACM certificate for: {domains} and got ARN: {certificate_arn}")

        return certificate_arn

    except Exception as e:
        logger.exception(f"An error occurred: {e}")
        return None


def check_certificate_validation(certificate_arn):
    logger.info(f"Checking on ACM Certificate: {certificate_arn}")
    acm = create_aws_client('acm')
    cert_details = acm.describe_certificate(CertificateArn=certificate_arn)
    cert_details = cert_details['Certificate']
    # Check for expiration
    overall_health = "UNKNOWN"
    expiration_date = cert_details['NotAfter']
    # Convert expiration_date to be offset-naive
    expiration_date_naive = expiration_date.replace(tzinfo=None)
    if expiration_date_naive - timedelta(days=45) <= datetime.utcnow():
        overall_health = "NotHealthy"

    # Check for status
    statuses_to_check = [
        "PENDING_VALIDATION",
        "REVOKED",
        "EXPIRED",
        "FAILED",
        "VALIDATION_TIMED_OUT",
        "RENEWING"
    ]
    status = cert_details['Status']
    if status in statuses_to_check:
        overall_health = "NotHealthy"
    elif status == "ISSUED" and overall_health == "UNKNOWN":
        overall_health = "Healthy"

    return {
        "arn": certificate_arn,
        "status": cert_details.get('Status', None),
        "validations": cert_details.get('DomainValidationOptions', None),
        "expiration_date": str(cert_details['NotAfter']),
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
    if len(arns_to_delete) == 0:
        logger.info(f"Finished deleting all ACM Certificates with these tags: {aws_resource_tags}")
        return True
    else:
        logger.info(f"Still deleting all ACM Certificates with these tags: {aws_resource_tags}")
        return False
        
        


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
    
    cert = response.get('cert')
    privatekey = response.get('privkey')
    fullchain = response.get('fullchain')
        
    return cert, privatekey, fullchain


def get_serial_number(certificate_arn):
    acm = create_aws_client('acm')
    certificate = acm.describe_certificate(CertificateArn=certificate_arn)
    return certificate['Certificate']['Serial']

def import_cert_to_acm(secret_path_in_vault, aws_resource_tags):
    cert, privatekey, fullchain = get_cert_from_vault(secret_path_in_vault)
    serial_number_of_current_cert_from_secret_store = extract_serial_number_from_cert_string(cert)
    
    existing_cert_arns = get_resource_arns_using_tags(aws_resource_tags, ['acm:certificate'])
    for cert_arn in existing_cert_arns:
        acm_serial_number = get_serial_number(cert_arn)
        if serial_number_of_current_cert_from_secret_store.lower() == acm_serial_number.lower():
            logger.info(f"Looks like the certificate from Vault {secret_path_in_vault} is already in AWS ACM as: {cert_arn}")
            return cert_arn
    
    logger.info(f"Looks like the certificate from Vault {secret_path_in_vault} is not in AWS ACM. It's not being imported.")
    acm = create_aws_client('acm')
    
    response = acm.import_certificate(
        Certificate=cert,
        PrivateKey=privatekey,
        CertificateChain=fullchain,
        Tags=aws_resource_tags
    )
    
    return response['CertificateArn']
