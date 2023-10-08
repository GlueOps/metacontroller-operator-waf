from fastapi import FastAPI, HTTPException, Request
from utils.aws_acm import *
from utils.aws_cloudfront import *
from utils.vault import *
import glueops.logging
import glueops.certificates
import os
import traceback

logger = glueops.logging.configure()
app = FastAPI()

@app.post("/sync")
async def sync_endpoint(request: Request):
    try:
        observed = await request.json()
        desired = sync(observed["parent"], observed["children"])
        return desired
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/finalize")
async def finalize_endpoint(request: Request):
    try:
        data = await request.json()
        parent = data["parent"]
        aws_resource_tags = [
            {"Key": "kubernetes_resource_uid", "Value": parent["metadata"]["uid"]},
            {"Key": "captain_domain", "Value": os.environ.get('CAPTAIN_DOMAIN')}
        ]
        print(aws_resource_tags)
        return finalize_hook(aws_resource_tags)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def sync(parent, children):
    uid, aws_resource_tags, domains, custom_certificate_secret_store_path, status_dict, acm_arn, distribution_id, origin_domain = get_parent_data(parent)
    
    if "error_message" in status_dict:
        status_dict = {}
    
    try:
        cleanup_orphaned_certs(aws_resource_tags)

        if custom_certificate_secret_store_path is None:
            if acm_arn is None or need_new_certificate(acm_arn, domains) or is_cert_imported(acm_arn):
                logger.info("Requesting a new certificate")
                acm_arn = create_acm_certificate(domains, uid, aws_resource_tags)
        elif acm_arn is None or custom_certificate_secret_store_path is not None:
            acm_arn = import_cert_to_acm(custom_certificate_secret_store_path, aws_resource_tags)

        certificate_status = check_certificate_validation(acm_arn)
        status_dict["certificate_request"] = certificate_status

        if status_dict["certificate_request"]["status"] == "ISSUED":
            dist_request = status_dict.setdefault("distribution_request", {})

            if distribution_id is None:
                dist_request = create_distribution(origin_domain, acm_arn, None, domains, uid, aws_resource_tags=aws_resource_tags)
            else:
                dist_request = get_live_distribution_status(distribution_id)

                if dist_request["status"] != "InProgress":
                    update_distribution(distribution_id, origin_domain, acm_arn, None, domains)
                else:
                    logger.info(f"There are updates in progress for DISTRIBUTION ID: {distribution_id}. Skipping updates.")

            status_dict["distribution_request"] = dist_request
        
        return {"status": status_dict}

    except Exception as e:
        status_dict = {}
        status_dict["error_message"] = traceback.format_exc()
        return {"status": status_dict}

def finalize_hook(aws_resource_tags):
    try:
        if not delete_all_cloudfront_distributions(aws_resource_tags):
            logger.error("Failed to delete all CloudFront distributions. We will try again shortly.")
            return {"finalized": False}

        if not delete_all_acm_certificates(aws_resource_tags):
            logger.error("Failed to delete all ACM certificates after successfully deleting CloudFront distributions. We will try again shortly.")
            return {"finalized": False}

        return {"finalized": True}

    except Exception as e:
        logger.error(f"Unexpected exception occurred: {e}. We will try again shortly.")
        return {"finalized": False}

def get_parent_data(parent):
    uid = parent.get("metadata").get("uid")
    captain_domain = os.environ.get('CAPTAIN_DOMAIN')
    aws_resource_tags = [
        {"Key": "kubernetes_resource_uid", "Value": uid},
        {"Key": "captain_domain", "Value": captain_domain}
    ]
    origin_domain = f"ingress.{captain_domain}"
    domains = parent.get("spec", {}).get("domains")
    custom_certificate_secret_store_path = parent.get("spec", {}).get("custom_certificate_secret_store_path")
    status_dict = parent.get("status", {})
    acm_arn = status_dict.get("certificate_request", {}).get("arn", None)
    distribution_id = status_dict.get("distribution_request", {}).get("distribution_id", None)

    if not does_acm_cert_exist(acm_arn):
        acm_arn = None
    if not does_distribution_exist(distribution_id):
        distribution_id = None

    return uid, aws_resource_tags, domains, custom_certificate_secret_store_path, status_dict, acm_arn, distribution_id, origin_domain
