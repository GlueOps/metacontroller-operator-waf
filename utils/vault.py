import requests
import glueops.certificates
from fastapi import HTTPException
import glueops.setup_logging
import os

logger = glueops.setup_logging.configure(level=os.environ.get('LOG_LEVEL', 'WARNING'))



VAULT_ADDR = os.environ.get('VAULT_ADDR')
K8S_ROLE = os.environ.get('K8S_ROLE')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN')
POMERIUM_COOKIE = os.environ.get("POMERIUM_COOKIE")


def get_jwt_token():
    logger.info("Retrieving kubernetes service account token")
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as f:
        return f.read().strip()


def get_vault_token_via_kube_auth():
    jwt_token = get_jwt_token()
    payload = {
        "jwt": jwt_token,
        "role": K8S_ROLE
    }
    logger.info("Requesting client token from vault")
    response = requests.post(
        f"{VAULT_ADDR}/v1/auth/kubernetes/login", json=payload, verify=False)
    logger.info(f"Vault login response code: {response.status_code}")
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

    response = requests.get(f"{VAULT_ADDR}/v1/{secret_path}",
                            headers=headers, verify=False, allow_redirects=False)
    if response.headers.get('Location'):
        raise HTTPException(
            status_code=400, detail=f"We got a redirect response when trying to read a secret from Vault. You are probably using pomerium or something went wrong in cluster and your token expired.")

    # Check if the request itself was successful
    if response.status_code != 200:
        raise Exception(f"Error from Secret Store: {response.status_code}")

    # Attempt to parse the JSON response
    try:
        response_data = response.json()
    except ValueError:
        raise Exception("Unexpected response format from Secret Store.")

    if 'data' not in response_data:
        raise Exception("Missing data.")

    actual_data = response_data['data'].get('data')
    if not actual_data:
        raise Exception("Failed to get certificate from secret store")

    return actual_data
