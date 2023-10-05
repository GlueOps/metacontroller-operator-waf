import boto3
import time
from datetime import datetime, timezone
from deepdiff import DeepDiff

from json_log_formatter import JsonFormatter
import logging
logger = logging.getLogger('GLUEOPS_WAF_OPERATOR')
from utils.tools import *



def get_distribution_id_from_arn(arn):
    """Extract CloudFront Distribution ID from its ARN."""
    # Split the ARN by ':' and then by '/' to get the Distribution ID
    parts = arn.split(':')
    if len(parts) > 5:
        distribution_id = parts[5].split('/')[-1]
        return distribution_id
    return None


def create_distribution(origin_domain_name, acm_certificate_arn, web_acl_id, domains, resource_uid, aws_resource_tags):
    existing_distribution_arns = get_resource_arns_using_tags(aws_resource_tags, ['cloudfront:distribution'])
    if len(existing_distribution_arns) > 1:
        logger.exception("Something is wrong. There isn't a situation where we should have two distributions with the same tags. This requires manual cleanup.")
    for existing_distribution_arn in existing_distribution_arns:
        existing_distribution_id = get_distribution_id_from_arn(existing_distribution_arn)
        return get_live_distribution_status(existing_distribution_id)
            
            
    logger.info(f"Creating distribution for: {domains}")
    cdn = create_aws_client('cloudfront')
    DistributionConfigWithTags = { "DistributionConfig" : create_distribution_config(
        domains, origin_domain_name, acm_certificate_arn, web_acl_id, caller_reference=resource_uid),
                                  "Tags" : { "Items": aws_resource_tags }
                                  }
    response = cdn.create_distribution_with_tags(DistributionConfigWithTags=DistributionConfigWithTags)
    state = parse_distribution_state(response)
    return state


def update_distribution(distribution_id, origin_domain_name, acm_certificate_arn, web_acl_id, domains):
    cdn = create_aws_client('cloudfront')
    response = get_live_distribution_config(distribution_id)
    config = response['DistributionConfig']
    etag = response['ETag']
    caller_reference = response['DistributionConfig']['CallerReference']
    config_to_deploy = create_distribution_config(
        domains, origin_domain_name, acm_certificate_arn, web_acl_id, caller_reference)

    differences = DeepDiff(config, config_to_deploy, ignore_order=True)
    if differences:
        config['Enabled'] = True
        if config['Aliases']['Quantity'] == 0:
            config['Aliases']['Items'] = []
        differences = DeepDiff(config, config_to_deploy, ignore_order=True)
        if differences:
            logger.info(
                f"Updating Distribution ID: {distribution_id} because of: {differences}")
            cdn.update_distribution(
                DistributionConfig=config_to_deploy, Id=distribution_id, IfMatch=etag)


def get_live_distribution_status(distribution_id):
    logger.info(f"Getting Distribution status: {distribution_id}")
    client = create_aws_client('cloudfront')
    response = client.get_distribution(Id=distribution_id)
    return parse_distribution_state(response)


def parse_distribution_state(distribution_details):
    logger.info(f"Parsing distribution_state: {distribution_details}")
    state = {
        "status": distribution_details.get('Distribution', {}).get('Status', None),
        "arn": distribution_details.get('Distribution', {}).get('ARN', None),
        "distribution_id": distribution_details.get('Distribution', {}).get('Id', None),
        "distribution_enabled": distribution_details.get('Distribution', {}).get('DistributionConfig', {}).get('Enabled', None),
        "cloudfront_url": distribution_details.get('Distribution', {}).get('DomainName', None),
        "acm_certificate_arn":  distribution_details.get('Distribution', {}).get('DistributionConfig', {}).get('ViewerCertificate', None).get('ACMCertificateArn', None),
        "last_modified_time": str(distribution_details.get('Distribution', {}).get('LastModifiedTime', None))
    }
    logger.info(f"Parsed distribution details: {state}")

    return state


def get_live_distribution_config(distribution_id):
    logger.info(
        f"Getting current status of Distribution ID: {distribution_id}")
    client = create_aws_client('cloudfront')
    response = client.get_distribution_config(Id=distribution_id)
    return response


def disable_distribution(distribution_id, acm_arn):
    logger.info(f"Disabling Distribution ID: {distribution_id}")
    client = create_aws_client('cloudfront')
    config = get_live_distribution_config(distribution_id)
    etag = config['ETag']
    config = create_distribution_config(
        [], "glueops.dev", acm_arn, None, caller_reference=config['DistributionConfig']['CallerReference'])
    if config['Enabled']:
        config['Enabled'] = False
        client.update_distribution(
            DistributionConfig=config, Id=distribution_id, IfMatch=etag)


def delete_distribution(distribution_id):
    logger.info(
        f"Starting/Checking on deletion of Distribution ID: {distribution_id}")
    client = create_aws_client('cloudfront')
    state = get_live_distribution_status(distribution_id)
    config = get_live_distribution_config(distribution_id)
    etag = config['ETag']
    if state["distribution_enabled"] == True and state["status"] != "InProgress":
        logger.info("disabling distribution")
        disable_distribution(distribution_id, state["acm_certificate_arn"])
        state = get_live_distribution_status(distribution_id)
    if state["distribution_enabled"] == False and state["status"] != "InProgress":
        logger.info(state)
        logger.info(f"Deleting Distribution ID: {distribution_id}")
        client.delete_distribution(Id=distribution_id, IfMatch=etag)
        return True
    return False


def delete_all_cloudfront_distributions(aws_resource_tags):
    logger.info(f"Deleting all CloudFront distributions with these tags: {aws_resource_tags}")
    arns_to_delete = get_resource_arns_using_tags(aws_resource_tags, ['cloudfront:distribution'])
    for arn in arns_to_delete:
        id = get_distribution_id_from_arn(arn)
        delete_distribution(distribution_id=id)
    if len(arns_to_delete) == 0:
        logger.info(f"Finished all CloudFront distributions with these tags: {aws_resource_tags}")
        return True
    else:
        logger.info(f"Still deleting all CloudFront distributions with these tags: {aws_resource_tags}")
        return False
        

def create_distribution_config(domains, glueops_cluster_ingress_domain, acm_arn, web_acl_id=None, caller_reference=None):
    logger.info(f"Creating a Distribution config for: {domains}")
    if web_acl_id is None:
        web_acl_id = ""

    distribution_config = {
        "CallerReference": caller_reference,
        "Aliases": {
            "Quantity": len(domains),
            "Items": domains
        },
        "DefaultRootObject": "",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "glueops-cluster",
                    "DomainName": glueops_cluster_ingress_domain,
                    "OriginPath": "",
                    "CustomHeaders": {
                        "Quantity": 0
                    },
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "match-viewer",
                        "OriginSslProtocols": {
                            "Quantity": 3,
                            "Items": [
                                "TLSv1",
                                "TLSv1.1",
                                "TLSv1.2"
                            ]
                        },
                        "OriginReadTimeout": 60,
                        "OriginKeepaliveTimeout": 60
                    },
                    "ConnectionAttempts": 3,
                    "ConnectionTimeout": 10,
                    "OriginShield": {
                        "Enabled": False
                    },
                    "OriginAccessControlId": ""
                }
            ]
        },
        "OriginGroups": {
            "Quantity": 0
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "glueops-cluster",
            "TrustedSigners": {
                "Enabled": False,
                "Quantity": 0
            },
            "TrustedKeyGroups": {
                "Enabled": False,
                "Quantity": 0
            },
            "ViewerProtocolPolicy": "allow-all",
            "AllowedMethods": {
                "Quantity": 7,
                "Items": [
                    "HEAD",
                    "DELETE",
                    "POST",
                    "GET",
                    "OPTIONS",
                    "PUT",
                    "PATCH"
                ],
                "CachedMethods": {
                    "Quantity": 2,
                    "Items": [
                        "HEAD",
                        "GET"
                    ]
                }
            },
            "SmoothStreaming": False,
            "Compress": False,
            "LambdaFunctionAssociations": {
                "Quantity": 0
            },
            "FunctionAssociations": {
                "Quantity": 0
            },
            "FieldLevelEncryptionId": "",
            "ForwardedValues": {
                "QueryString": True,
                "Cookies": {
                    "Forward": "all"
                },
                "Headers": {
                    "Quantity": 1,
                    "Items": [
                        "*"
                    ]
                },
                "QueryStringCacheKeys": {
                    "Quantity": 0
                }
            },
            "MinTTL": 0,
            "DefaultTTL": 0,
            "MaxTTL": 86400
        },
        "CacheBehaviors": {
            "Quantity": 0
        },
        "CustomErrorResponses": {
            "Quantity": 0
        },
        "Comment": "Managed by GlueOps Controller",
        "Logging": {
            "Enabled": False,
            "IncludeCookies": False,
            "Bucket": "",
            "Prefix": ""
        },
        "PriceClass": "PriceClass_100",
        "Enabled": True,
        "ViewerCertificate": {
            "CloudFrontDefaultCertificate": False,
            "ACMCertificateArn": acm_arn,
            "SSLSupportMethod": "sni-only",
            "MinimumProtocolVersion": "TLSv1",
            "Certificate": acm_arn,
            "CertificateSource": "acm"
        },
        "Restrictions": {
            "GeoRestriction": {
                "RestrictionType": "none",
                "Quantity": 0
            }
        },
        "WebACLId": web_acl_id,
        "HttpVersion": "http2",
        "IsIPV6Enabled": True,
        "ContinuousDeploymentPolicyId": "",
        "Staging": False
    }

    logger.info(distribution_config)

    return distribution_config
