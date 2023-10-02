from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from tools import *



class Controller(BaseHTTPRequestHandler):
  def sync(self, parent, children):
    # Compute status based on observed state.
    # desired_status = {
    #   "pods": len(children["Pod.v1"])
    # }
    print("Yolo")
    status_dict = {"status": {}}
    domains = parent.get("spec", {}).get("domains")
    arn = create_acm_certificate(domains)
    certificate_status = check_certificate_validation(arn)
    status_dict["status"]["certificate_request"] = certificate_status
    
    if "status" in check_certificate_validation(arn):
        if check_certificate_validation(arn).get("status") == "ISSUED":
          print('make cdn and waf please')
    
    
    existing_conditions = [
        {"type": "Ready", "status": "True", "lastTransitionTime": "2023-10-02T17:30:00Z"},
        {"type": "Initialized", "status": "True", "lastTransitionTime": "2023-10-02T17:20:00Z"}
    ]

    new_conditions = [
        {"type": "Ready", "status": "False"},  # Here the status changed, so this condition should get a new lastTransitionTime
        {"type": "Initialized", "status": "True"},  # Here the status is same, so this condition should retain the old lastTransitionTime
        {"type": "Available", "status": "True"}  # This is a new condition, so it should get a new lastTransitionTime
    ]

    updated_conditions = update_conditions(existing_conditions, new_conditions)
    status_payload = { "status":{
        "conditions": "updated_conditions"
    }}

    return status_dict
    #return { "finalized": True}
#{"status": desired_status, "children": desired_pods}

  def do_POST(self):
    # Serve the sync() function as a JSON webhook.
    observed = json.loads(self.rfile.read(int(self.headers.get("content-length"))))
    desired = self.sync(observed["parent"], observed["children"])
    print(desired)
    self.send_response(200)
    self.send_header("Content-type", "application/json")
    self.end_headers()
    self.wfile.write(json.dumps(desired).encode())

HTTPServer(("", 8081), Controller).serve_forever()
