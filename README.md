# metacontroller-operator-waf


For local development all of the following need to be configured:

```bash
export AWS_ACCESS_KEY_ID= 
export AWS_SECRET_ACCESS_KEY= 
export AWS_DEFAULT_REGION=us-east-1 #this needs to be the cloudfront region
export VAULT_ADDR="https://vault-url" # If you set the pomerium cookie below you can use the public url
export VAULT_TOKEN="hvs.CAESIM1u" # Get this by logging into vault in the browser, clicking on your profile and then clicking on "Copy token"
export POMERIUM_COOKIE= # Get this from the cookie in your browser "_pomerium"
export CAPTAIN_DOMAIN=
```
