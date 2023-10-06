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

# configure logging
json_formatter = JsonFormatter()

handler = logging.StreamHandler()
handler.setFormatter(json_formatter)

logger = logging.getLogger('GLUEOPS_WAF_OPERATOR')
logger.setLevel(logging.INFO)
logger.addHandler(handler)


class Controller(BaseHTTPRequestHandler):

    def sync(self, parent, children):
        uid = parent.get("metadata").get("uid")
        aws_resource_tags = [
            {
                "Key": "kubernetes_resource_uid",
                "Value": uid
            },
            {
                "Key": "captain_domain",
                "Value": os.environ.get('CAPTAIN_DOMAIN', 'local-development')
            }
        ]
        domains = parent.get("spec", {}).get("domains")
        status_dict = parent.get("status", {})
        acm_arn = status_dict.get("certificate_request", {}).get("arn", None)
        distribution_id = status_dict.get(
            "distribution_request", {}).get("distribution_id", None)
        
        # in case something gets deleted outside of kubernetes setting these to None will let them be recreated by the controller
        if not does_acm_cert_exist(acm_arn):
            acm_arn = None
        if not does_distribution_exist(distribution_id):
            distribution_id = None
            
            
        if self.path.endswith('/sync'):
            if acm_arn is not None:
                if need_new_certificate(acm_arn, domains):
                    logger.info("Requesting a new certificate")
                    acm_arn = create_acm_certificate(
                        domains, uid, aws_resource_tags)
                certificate_status = check_certificate_validation(acm_arn)
                status_dict["certificate_request"] = certificate_status
            elif acm_arn is None:
                acm_arn = create_acm_certificate(
                    domains, uid, aws_resource_tags)
                certificate_status = check_certificate_validation(acm_arn)
                status_dict["certificate_request"] = certificate_status

            if status_dict["certificate_request"]["status"] == "ISSUED":
                if distribution_id is None:
                    status_dict["distribution_request"] = create_distribution(
                        "yahoo.com", acm_arn, None, domains, uid, aws_resource_tags=aws_resource_tags)
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
            try:
                if delete_all_cloudfront_distributions(aws_resource_tags):
                    if delete_all_acm_certificates(aws_resource_tags):
                        return {"finalized": True}
            except Exception as e:
                logger.error(f"Exception when trying to delete all ACM and CloudFront Resources. We will try again shortly. Exception {e}")
                

        return {"status": status_dict}

    semaphore = threading.Semaphore(100)

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
