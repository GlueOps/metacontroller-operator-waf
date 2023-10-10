from glueops.aws import *
import glueops.setup_logging
import os

log_level = getattr(glueops.setup_logging,
                    os.environ.get('LOG_LEVEL', 'WARNING'))
logger = glueops.setup_logging.configure(log_level=log_level)


def get_webacl_arn_from_name(name, scope='CLOUDFRONT'):
    # Create WAFv2 client
    waf = create_aws_client('wafv2')

    # Call list_web_acls to retrieve the list of WebACLs
    response = waf.list_web_acls(Scope=scope)

    # Loop through the WebACLs and match by name
    for web_acl in response['WebACLs']:
        if web_acl['Name'] == name:
            return web_acl['ARN']

    raise Exception(f"Unable to find Web ACL with name: {name}")
