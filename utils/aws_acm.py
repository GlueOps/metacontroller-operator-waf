import boto3
import time
from datetime import datetime, timezone
from deepdiff import DeepDiff

from json_log_formatter import JsonFormatter
import logging
logger = logging.getLogger('GLUEOPS_WAF_OPERATOR')
from utils.tools import *

def create_acm_certificate(domains, uid, aws_resource_tags):
    logging.info(f"Creating ACM certificate for: {domains}")
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

    return {
        "arn": certificate_arn,
        "status": cert_details.get('Certificate', {}).get('Status', None),
        "validations": cert_details.get('Certificate', {}).get('DomainValidationOptions', None)
    }


def delete_acm_certificate(certificate_arn):
    logger.info(f"Deleting ACM Certificate {certificate_arn}")
    acm = create_aws_client('acm')
    acm.delete_certificate(CertificateArn=certificate_arn)


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
