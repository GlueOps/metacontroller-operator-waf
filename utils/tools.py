import boto3
import time
from datetime import datetime, timezone
from deepdiff import DeepDiff

from json_log_formatter import JsonFormatter
import logging
logger = logging.getLogger('GLUEOPS_WAF_OPERATOR')


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


def create_bad_state():
    print("This is running to create a bad state in the application and help test automated recovery")
    raise Exception("This is running to create a bad state in the application and help test automated recovery")
