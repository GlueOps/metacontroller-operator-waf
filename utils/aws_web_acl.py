from glueops.aws import *
import glueops.logging

logger = glueops.logging.configure()


def get_webacl_arn_from_name(name, scope='CLOUDFRONT'):
    # Create WAFv2 client
    waf = create_aws_client('wafv2')

    # Initialize pagination
    paginator = waf.get_paginator('list_web_acls')
    iterator = paginator.paginate(Scope=scope)

    # Loop through the WebACLs and match by name
    for page in iterator:
        for web_acl in page['WebACLs']:
            if web_acl['Name'] == name:
                return web_acl['ARN']
            
    raise Exception(f"Unable to find Web ACL with name: {name}")
