import boto3
import time
from datetime import datetime, timezone
from deepdiff import DeepDiff

from json_log_formatter import JsonFormatter
import logging
logger = logging.getLogger('GLUEOPS_WAF_OPERATOR')
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def create_aws_client(service):
    return boto3.client(service, region_name='us-east-1')


def get_resource_arns_using_tags(tags, aws_resource_filter):
    """Retrieve ARNs of resources with specific tags."""
    logger.info(f"Checking to see if this certificate was already requested/created with tags: {tags}")
    tagging = create_aws_client('resourcegroupstaggingapi')
    tags = {item['Key']: item['Value'] for item in tags}
    response = tagging.get_resources(
        TagFilters=[
            {'Key': key, 'Values': [value]} for key, value in tags.items()
        ],
        ResourceTypeFilters=aws_resource_filter # ['cloudfront:distribution'] or ['acm:certificate']
    )

    arns = [item['ResourceARN']
            for item in response.get('ResourceTagMappingList', [])]
    if len(arns) == 0:
        logger.info(f"Found existing arns: {arns} with: {tags}")
    else:
        logger.info(f"No certificate existed with tags: {tags}")
        
    return arns

def extract_serial_number_from_cert_string(cert_string):
    certificate = x509.load_pem_x509_certificate(cert_string.encode(), default_backend())
    decimal_serial = certificate.serial_number
    # Convert to hexadecimal
    hex_serial = format(decimal_serial, 'X')
    # Ensure an even number of digits for correct byte representation
    if len(hex_serial) % 2 != 0:
        hex_serial = '0' + hex_serial
    # Insert colons between every 2 characters
    colon_separated_serial = ":".join(hex_serial[i:i+2] for i in range(0, len(hex_serial), 2))
    return colon_separated_serial
