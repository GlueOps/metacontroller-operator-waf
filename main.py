from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from tools import *
from json_log_formatter import JsonFormatter
import logging


# configure logging
json_formatter = JsonFormatter()

handler = logging.StreamHandler()
handler.setFormatter(json_formatter)

logger = logging.getLogger('GLUEOPS_WAF_OPERATOR')
logger.setLevel(logging.INFO)
logger.addHandler(handler)


class Controller(BaseHTTPRequestHandler):
    def sync(self, parent, children):
        # Compute status based on observed state.
        # desired_status = {
        #   "pods": len(children["Pod.v1"])
        # }
        domains = parent.get("spec", {}).get("domains")
        status_dict = parent.get("status", {})
        acm_arn = status_dict.get("certificate_request", {}).get("arn", None)
        distribution_id = status_dict.get(
            "distribution_request", {}).get("distribution_id", None)

        if self.path.endswith('/sync'):
            if acm_arn is not None:
                if need_new_certificate(acm_arn, domains):
                    logger.info("Requesting a new certificate")
                    acm_arn = create_acm_certificate(domains)
                certificate_status = check_certificate_validation(acm_arn)
                status_dict["certificate_request"] = certificate_status
            elif acm_arn is None:
                acm_arn = create_acm_certificate(domains)
                certificate_status = check_certificate_validation(acm_arn)
                status_dict["certificate_request"] = certificate_status

            if status_dict["certificate_request"]["status"] == "ISSUED":
                if distribution_id is None:
                    status_dict["distribution_request"] = create_distribution(
                        "yahoo.com", acm_arn, None, domains)
                if distribution_id is not None:
                    status_dict["distribution_request"] = get_live_distribution_status(
                        distribution_id)
                    if status_dict["distribution_request"]["status"] != "InProgress":
                        update_distribution(
                            distribution_id, "yahoo.com", acm_arn, None, domains)
                    else:
                        logger.info(
                            f"There are updates in progress for DISTRIBUTION ID: {distribution_id} so we are going to skip any updates now")

        if self.path.endswith('/finalize'):
            logger.info(
                f"Deleting Distribution ID: {distribution_id} and ACM CERT: {acm_arn}")
            if distribution_id is not None:
                if delete_distribution(distribution_id, acm_arn):
                    status_dict["distribution_request"] = {}
            if acm_arn is not None and distribution_id is None:
                delete_acm_certificate(acm_arn)
                logger.info(
                    f"Successfully Deleted Distribution ID: {distribution_id} and ACM CERT: {acm_arn}")
                return {"finalized": True}
            if distribution_id is None and acm_arn is None:
                return {"finalized": True}

        return {"status": status_dict}

    def do_POST(self):
        # Serve the sync() function as a JSON webhook.
        observed = json.loads(self.rfile.read(
            int(self.headers.get("content-length"))))
        desired = self.sync(observed["parent"], observed["children"])
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(desired).encode())


HTTPServer(("", 8080), Controller).serve_forever()
