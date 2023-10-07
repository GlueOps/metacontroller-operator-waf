from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import json
from utils.aws_acm import *
from utils.aws_cloudfront import *
from json_log_formatter import JsonFormatter
import logging
import threading
import signal
import socket
import os
from utils.vault import *

# configure logging
json_formatter = JsonFormatter()

handler = logging.StreamHandler()
handler.setFormatter(json_formatter)

logger = logging.getLogger('GLUEOPS_WAF_OPERATOR')
logger.setLevel(logging.INFO)
logger.addHandler(handler)


class Controller(BaseHTTPRequestHandler):

    semaphore = threading.Semaphore(100)

    def sync(self, parent, children):
        uid, aws_resource_tags, domains, custom_certificate_secret_store_path, status_dict, acm_arn, distribution_id, origin_domain = self._get_parent_data(parent)
        if "error_message" in status_dict:
            status_dict = {}
        try:
            if self.path.endswith('/sync'):
                cleanup_orphaned_certs(aws_resource_tags)
                # Handle certificate requests
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
                        dist_request = create_distribution(
                            origin_domain, acm_arn, None, domains, uid, aws_resource_tags=aws_resource_tags)
                    else:
                        dist_request = get_live_distribution_status(distribution_id)

                        if dist_request["status"] != "InProgress":
                            update_distribution(distribution_id, origin_domain, acm_arn, None, domains)
                        else:
                            logger.info(
                                f"There are updates in progress for DISTRIBUTION ID: {distribution_id}. Skipping updates.")
                    
                    status_dict["distribution_request"] = dist_request

            if self.path.endswith('/finalize'):
                return self.finalize_hook(aws_resource_tags)
            
            return {"status": status_dict}
        except Exception as e:
            status_dict = {}
            status_dict["error_message"] = str(e)
            return {"status": status_dict}

    def finalize_hook(self, aws_resource_tags):
        try:
            if not delete_all_cloudfront_distributions(aws_resource_tags):
                logger.error("Failed to delete all CloudFront distributions. We will try again shortly.")
                return

            if not delete_all_acm_certificates(aws_resource_tags):
                logger.error("Failed to delete all ACM certificates after successfully deleting CloudFront distributions. We will try again shortly.")
                return

            return {"finalized": True}
            
        except Exception as e:
            logger.error(f"Unexpected exception occurred: {e}. We will try again shortly.")
    
    def _get_parent_data(self, parent):
        uid = parent.get("metadata").get("uid")
        captain_domain = os.environ.get('CAPTAIN_DOMAIN')
        aws_resource_tags = [
            {"Key": "kubernetes_resource_uid", "Value": uid},
            {"Key": "captain_domain",
             "Value": captain_domain}
        ]
        origin_domain = f"ingress.{captain_domain}"
        domains = parent.get("spec", {}).get("domains")
        custom_certificate_secret_store_path = parent.get("spec", {}).get("custom_certificate_secret_store_path")
        status_dict = parent.get("status", {})
        acm_arn = status_dict.get("certificate_request", {}).get("arn", None)
        distribution_id = status_dict.get(
            "distribution_request", {}).get("distribution_id", None)
        
        # in case something gets deleted outside of kubernetes setting these to None will let them be recreated by the controller
        if not does_acm_cert_exist(acm_arn):
            acm_arn = None
        if not does_distribution_exist(distribution_id):
            distribution_id = None
            
        return uid, aws_resource_tags, domains, custom_certificate_secret_store_path, status_dict, acm_arn, distribution_id, origin_domain

    def do_POST(self):
        try:
            acquired = Controller.semaphore.acquire(blocking=False)
            if not acquired:
                self.send_response(429)  # 429 Too Many Requests
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(
                    {"error": "Too many requests, please try again later."}).encode())
                return

            # Serve the sync() function as a JSON webhook.
            observed = json.loads(self.rfile.read(
                int(self.headers.get("content-length"))))
            desired = self.sync(observed["parent"], observed["children"])

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(desired).encode())
        except Exception as e:
            # Handle generic exceptions (like writing issues) here
            # Logging the exception could be beneficial
            print(f"Error occurred: {e}")
        finally:
            if acquired:
                Controller.semaphore.release()


# HTTPServer(("", 8080), Controller).serve_forever()


def run(server_class=HTTPServer, handler_class=Controller, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

    # Set a timeout on the socket to periodically check the shutdown flag
    httpd.timeout = 1  # 1 second

    # Signal handler for graceful shutdown
    should_shutdown = False

    def sig_handler(_signo, _stack_frame):
        nonlocal should_shutdown  # Use nonlocal since we're in a nested function
        should_shutdown = True
        logger.info("Received signal. Shutting down soon.")

    # Register signals
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    logger.info(f'Starting server on port {port}')
    while not should_shutdown:
        try:
            httpd.handle_request()
        except socket.timeout:
            continue

    logger.info("Server has shut down.")
    
    


run()
