import requests
import os
import glueops.logging
import glueops.certificates
from fastapi import HTTPException
logger = glueops.logging.configure()


VAULT_ADDR = os.environ.get('VAULT_ADDR')
K8S_ROLE = os.environ.get('K8S_ROLE')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN')
POMERIUM_COOKIE = os.environ.get("POMERIUM_COOKIE")

def get_jwt_token():
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as f:
        return f.read().strip()

def get_vault_token_via_kube_auth():
    jwt_token = get_jwt_token()
    payload = {
        "jwt": jwt_token,
        "role": K8S_ROLE
    }
    response = requests.post(f"{VAULT_ADDR}/v1/auth/kubernetes/login", json=payload, verify=False)
    response.raise_for_status()
    return response.json()["auth"]["client_token"]

def adjust_path(value):
    if value.startswith("secret/"):
        return value.replace("secret/", "secret/data/")
    return value

def get_data_from_vault(secret_path):
    logger.info(f"Getting data from secret store (vault): {secret_path}")
    if not VAULT_TOKEN:
        vault_token = get_vault_token_via_kube_auth()
    else:
        vault_token = VAULT_TOKEN
    
    secret_path = adjust_path(secret_path)
    headers = {
        'X-Vault-Token': vault_token
    }
    if POMERIUM_COOKIE:
        headers["cookie"] = f"_pomerium={POMERIUM_COOKIE}"

    response = requests.get(f"{VAULT_ADDR}/v1/{secret_path}", headers=headers, verify=False, allow_redirects=False)
    if response.headers.get('Location'):
        raise HTTPException(status_code=400, detail=f"We got a redirect response when trying to read a secret from Vault. You are probably using pomerium or something went wrong in cluster and your token expired.")

    response_data = response.json().get('data').get('data')
    if not response_data:
        raise HTTPException(status_code=404, detail=f"Failed to retrieve certificate data from Vault.")
    return response_data
