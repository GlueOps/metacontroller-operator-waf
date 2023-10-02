import boto3
import time
from datetime import datetime, timezone


def create_aws_client():
    return boto3.client('acm', region_name='us-east-1')


def create_acm_certificate(domains):
    if not domains:
        raise ValueError("At least one domain is required")

    main_domain = domains[0]
    alternative_names = domains[1:]

    # change the region as needed
    acm = create_aws_client()

    try:
        response = acm.request_certificate(
            DomainName=main_domain,
            ValidationMethod='DNS',  # this example is for DNS validation
            SubjectAlternativeNames=alternative_names,
            IdempotencyToken='glueops'  # this should be a unique string value. This can be anything as long as it's the same per unique request. But probably just best to leave it hardcoded to glueops. If the same certificate gets requested in the same hour it'll help avoid duplicates
        )

        certificate_arn = response['CertificateArn']
        print(f"Certificate requested with ARN: {certificate_arn}")

        return certificate_arn

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def check_certificate_validation(certificate_arn):
    acm = create_aws_client()
    cert_details = acm.describe_certificate(CertificateArn=certificate_arn)
    status = cert_details['Certificate']['Status']
    
    return {
        "status": cert_details['Certificate']['Status'],
        "validations": cert_details['Certificate']['DomainValidationOptions']
    }

# domains = ["yolo2.venkatamutyala.com", "venkatamutyala.com"]
# certificate_arn = create_acm_certificate(domains)

# if not certificate_arn:
#     print("Certificate creation failed.")


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
