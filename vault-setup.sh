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

# make two roles with different OUs to ensure we get metrics for the same CN with different OUs
vault write pki/roles/foo-role \
    allowed_domains=my-website.com \
    allow_subdomains=true \
    max_ttl=72h \
    ou="Foo"

vault write pki/roles/bar-role \
    allowed_domains=my-website.com \
    allow_subdomains=true \
    max_ttl=72h \
    ou="Bar"

apk add jq

# Test revoking a certificate for CRL metrics
CERT_OUTPUT=$(vault write -format=json pki/issue/foo-role common_name=www.revokme.my-website.com)
CERT_SERIAL=$(echo $CERT_OUTPUT | jq -r '.data.serial_number')
vault write pki/revoke serial_number="$CERT_SERIAL"

# issue 2 certs with same CNs but different OUs - want metrics for both
vault write pki/issue/foo-role \
    common_name=www.duplicate-ou-cert.my-website.com

vault write pki/issue/bar-role \
    common_name=www.duplicate-ou-cert.my-website.com

vault read pki/crl/rotate

# make non-default second issuer
# help test getting multiple CRLs
vault write pki/root/generate/internal \
    common_name=mysecondwebsite.com \
    ttl=8760h \
    issuer_name=second

vault write pki/roles/second-role \
    allowed_domains=mysecondwebsite.com \
    allow_subdomains=true \
    max_ttl=72h \
    issuer_ref=second

vault write pki/issue/second-role \
    common_name=www.mysecondwebsite.com

tail -f /dev/null
