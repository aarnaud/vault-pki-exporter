#!/bin/sh

## NOTE
## tests should be run with venom (tests.yml)
## but this file is still useful for local development

# Start the Vault server in the background
# vault server -config=/vault/config/config.hcl &
vault server -dev -dev-listen-address="0.0.0.0:8200" &

# Wait for Vault to start
while ! vault status > /dev/null 2>&1; do
    sleep 1
done

# https://developer.hashicorp.com/vault/docs/secrets/pki/setup
vault secrets enable pki

vault secrets tune -max-lease-ttl=87600h pki

 vault write pki/root/generate/internal \
    common_name=my-website.com \
    ttl=8760h

vault write pki/config/urls \
    issuing_certificates="http://vault:8200/v1/pki/ca" \
    crl_distribution_points="http://vault:8200/v1/pki/crl"


vault write pki/config/crl expiry="400h"

vault write pki/roles/example-dot-com \
    allowed_domains=my-website.com \
    allow_subdomains=true \
    max_ttl=72h

apk add jq
# test revoking a certificate for CRL metrics
CERT_OUTPUT=$(vault write -format=json pki/issue/example-dot-com common_name=www.revokme.my-website.com)
CERT_SERIAL=$(echo $CERT_OUTPUT | jq -r '.data.serial_number')
vault write pki/revoke serial_number="$CERT_SERIAL"

vault write pki/issue/example-dot-com \
    common_name=www.my-website.com

vault read pki/crl/rotate

tail -f /dev/null
