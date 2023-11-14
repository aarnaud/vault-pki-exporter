#!/bin/sh

mkdir /vault/data
# Start the Vault server in the background
# vault server -config=/vault/config/config.hcl &
vault server -dev -dev-listen-address="0.0.0.0:8200" &

# Wait for Vault to start
while ! vault status > /dev/null 2>&1; do
    sleep 1
done

# Initialize and unseal Vault (if needed)
# vault operator init ...
# vault operator unseal ...

# https://developer.hashicorp.com/vault/docs/secrets/pki/setup
# Enable the PKI secrets engine
vault secrets enable pki

# Set the maximum lease TTL for the PKI secrets engine
vault secrets tune -max-lease-ttl=87600h pki

# Generate a root certificate (or use an existing one)
# vault write -field=certificate pki/root/generate/internal \
#     common_name="example.com" \
#     ttl=87600h > CA_cert.crt

 vault write pki/root/generate/internal \
    common_name=my-website.com \
    ttl=8760h

vault write pki/config/urls \
    issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" \
    crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"

vault write pki/roles/example-dot-com \
    allowed_domains=my-website.com \
    allow_subdomains=true \
    max_ttl=72h

vault write pki/issue/example-dot-com \
    common_name=www.my-website.com

# Issue a certificate
# vault write pki/issue/example-dot-com \
#     common_name="www.example.com" \
#     ttl="24h" > example_cert.crt

# Your additional setup here...

tail -f /dev/null