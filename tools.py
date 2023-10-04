import boto3
import time
from datetime import datetime, timezone
from deepdiff import DeepDiff

from json_log_formatter import JsonFormatter
import logging
logger = logging.getLogger('GLUEOPS_WAF_OPERATOR')


def create_aws_client(service):
    return boto3.client(service, region_name='us-east-1')


def create_acm_certificate(domains):
    logging.info(f"Creating ACM certificate for: {domains}")
    if not domains:
        raise ValueError("At least one domain is required")

    main_domain = domains[0]

    alternative_names = domains[1:]

    # change the region as needed
    acm = create_aws_client('acm')
    response = None
    try:
        if len(alternative_names) == 0:
            response = acm.request_certificate(
                DomainName=main_domain,
                ValidationMethod='DNS',  # this example is for DNS validation
                # this should be a unique string value. This can be anything as long as it's the same per unique request. But probably just best to leave it hardcoded to glueops. If the same certificate gets requested in the same hour it'll help avoid duplicates
                IdempotencyToken=str(int(time.time()))
            )
        else:
            response = acm.request_certificate(
                DomainName=main_domain,
                ValidationMethod='DNS',  # this example is for DNS validation
                SubjectAlternativeNames=alternative_names,
                # this should be a unique string value. This can be anything as long as it's the same per unique request. But probably just best to leave it hardcoded to glueops. If the same certificate gets requested in the same hour it'll help avoid duplicates
                IdempotencyToken=str(int(time.time()))
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


def update_conditions(existing_conditions, new_conditions):
    updated_conditions = []

    for new_condition in new_conditions:
        # find the corresponding existing condition
        existing_condition = next(
            (cond for cond in existing_conditions if cond['type'] == new_condition['type']), None)

        if existing_condition:
            # if the status is the same, keep the existing condition
            if existing_condition['status'] == new_condition['status']:
                updated_conditions.append(existing_condition)
                continue
            # if the status is different, update the condition and set a new lastTransitionTime
            else:
                new_condition['lastTransitionTime'] = datetime.now(
                    timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # if the condition type does not exist in the existing conditions, it’s a new condition; set lastTransitionTime
        else:
            new_condition['lastTransitionTime'] = datetime.now(
                timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        updated_conditions.append(new_condition)

    return updated_conditions


def create_distribution(origin_domain_name, acm_certificate_arn, web_acl_id, domains):
    logger.info(f"Creating distribution for: {domains}")
    cdn = create_aws_client('cloudfront')
    response = cdn.create_distribution(DistributionConfig=create_distribution_config(
        domains, origin_domain_name, acm_certificate_arn))
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
    logger.info(f"Parsing distribution_state: {state}")
    state = {
        "status": distribution_details.get('Distribution', {}).get('Status', None),
        "arn": distribution_details.get('Distribution', {}).get('ARN', None),
        "distribution_id": distribution_details.get('Distribution', {}).get('Id', None),
        "distribution_enabled": distribution_details.get('Distribution', {}).get('DistributionConfig', {}).get('Enabled', None),
        "cloudfront_url": distribution_details.get('Distribution', {}).get('DomainName', None),
        "last_modified_time": str(distribution_details.get('Distribution', {}).get('LastModifiedTime', None))
    }

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


def delete_distribution(distribution_id, acm_arn):
    logger.info(
        f"Starting/Checking on deletion of Distribution ID: {distribution_id}")
    client = create_aws_client('cloudfront')
    state = get_live_distribution_status(distribution_id)
    config = get_live_distribution_config(distribution_id)
    etag = config['ETag']
    if state["distribution_enabled"] == True and state["status"] != "InProgress":
        logger.info("disabling distribution")
        disable_distribution(distribution_id, acm_arn)
        state = get_live_distribution_status(distribution_id)
    if state["distribution_enabled"] == False and state["status"] != "InProgress":
        logger.info(state)
        logger.info(f"Deleting Distribution ID: {distribution_id}")

        client.delete_distribution(Id=distribution_id, IfMatch=etag)
        return True
    return False


def create_distribution_config(domains, glueops_cluster_ingress_domain, acm_arn, web_acl_id=None, caller_reference=None):
    logger.info(f"Creating a Distribution config for: {domains}")
    if web_acl_id is None:
        web_acl_id = ""

    if caller_reference is None:
        caller_reference = str(int(time.time()))

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
