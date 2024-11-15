# vault-pki-exporter

> Export PKI Certificate and CRL metrics base on dates

## Vault integration

Compatibility with all environment variable use by vault cli

Example:

```console
VAULT_SKIP_VERIFY=true;
VAULT_ADDR=https://vault.hostname.com;
VAULT_CLIENT_KEY=mycert.pem;
VAULT_CLIENT_CERT=mycert.pem;
VAULT_AUTH_METHOD=oidc
```

`VAULT_AUTH_METHOD` is not native in vault cli but used in this application. Valid values:

- `oidc`
- `k8s`

- When set to oidc, will authenticate using oidc method, you can customize auth mount point by setting VAULT_AUTH_MOUNT.
- When set to k8s, will authenticate using kubernetes auth method. You should also set VAULT_K8S_ROLE to vault k8s role name and optionally specify VAULT_AUTH_MOUNT for custom auth mount name.

## Usage

```console
Usage:
   [flags]
   [command]

Available Commands:
  help        Help about any command
  version     Print the version.

Flags:
      --fetch-interval duration     How many sec between fetch certs on vault (default 1m0s)
  -h, --help                        help for this command
      --influx                      Enable InfluxDB Line Protocol
      --port int                    Prometheus exporter HTTP port (default 9333)
      --prometheus                  Enable prometheus exporter, default if nothing else
      --refresh-interval duration   How many sec between metrics update (default 1m0s)
      --batch-size-percent          How large of a batch of certificates to get data for at once, supports floats (e.g 0.0 - 100.0) (default 1)
      --log-level                   Set log level (options: info, warn, error, debug)
  -v, --verbose                     (deprecated) Enable verbose logging. Defaults to debug level logging

Use " [command] --help" for more information about a command.
```

## InfluxDB Line Protocol

```console
x509_crl,host=your.hostname.com,source=pki-test/ expiry=245124i,nextupdate=1573235993i 1572990868
x509_cert,common_name=My\ PKI\ CA,country=CA,host=your.hostname.com,locality=Montreal,organization=Example,organizational_unit=WebService,province=QC,serial=0e-50-38-4d-18-69-52-54-1d-71-31-49-1b-a8-06-c7-4f-23-64-26,source=pki-test/ age=14106i,enddate=1573408792i,expiry=417923i,startdate=1572976762i 1572990868
```

## Prometheus exporter

```console
# HELP x509_crl_expiry
# TYPE x509_crl_expiry gauge
x509_crl_expiry{source="pki-test/", issuer="example.com"} 243687.999819847
# HELP x509_crl_nextupdate
# TYPE x509_crl_nextupdate gauge
x509_crl_nextupdate{source="pki-test/", issuer="example.com"} 1.573235993e+09
# HELP x509_cert_age
# TYPE x509_cert_age gauge
x509_cert_age{common_name="My PKI CA",country="CA",locality="Montreal",organization="Example",organizational_unit="WebService",province="QC",serial="0e-50-38-4d-18-69-52-54-1d-71-31-49-1b-a8-06-c7-4f-23-64-26",source="pki-test/"} 15543.000180153
# HELP x509_cert_enddate
# TYPE x509_cert_enddate gauge
x509_cert_enddate{common_name="My PKI CA",country="CA",locality="Montreal",organization="Example",organizational_unit="WebService",province="QC",serial="0e-50-38-4d-18-69-52-54-1d-71-31-49-1b-a8-06-c7-4f-23-64-26",source="pki-test/"} 1.573408792e+09
# HELP x509_cert_expiry
# TYPE x509_cert_expiry gauge
x509_cert_expiry{common_name="My PKI CA",country="CA",locality="Montreal",organization="Example",organizational_unit="WebService",province="QC",serial="0e-50-38-4d-18-69-52-54-1d-71-31-49-1b-a8-06-c7-4f-23-64-26",source="pki-test/"} 416486.999819847
# HELP x509_cert_startdate
# TYPE x509_cert_startdate gauge
x509_cert_startdate{common_name="My PKI CA",country="CA",locality="Montreal",organization="Example",organizational_unit="WebService",province="QC",serial="0e-50-38-4d-18-69-52-54-1d-71-31-49-1b-a8-06-c7-4f-23-64-26",source="pki-test/"} 1.572976762e+09
```

## Batch Size

Vault PKI Exporter supports a `--batch-size-percent` flag to batch many requests for individual certificate metrics at once.

If you are getting many log messages such as:

```console
level=error msg="failed to get certificate for pki/26:97:08:32:44:40:30:de:11:5z:ef:07:64:91:1e:9c:db:93:8c:1f, got error: Get \"https://vault.domain.com:8200/v1/pki/cert/26:97:08:32:44:40:30:de:11:5z:ef:07:64:91:1e:9c:db:93:8c:1f\": EOF"
```

Your batch size is probably too high.

## Certificate Selection

Any certificate with a unique subject common name and organizational unit is considered for metrics. If a certificate is renewed in place with the same CN and OU, it will still retain the same time series to avoid false alarms.

Revoked certificates are not considered for metrics and their time series will be deleted when an "active" certificate is deleted.

Expired certificates still retain their time series too.

## PKI Engine Selection

Right now the exporter will find any Vault PKI secrets engines and attempt to get certs for all of them. PKI secrets engines are currently not selectable by the exporter.

## Contributing

### Testing

Venom is used for tests, run `sudo venom run tests.yml` to perform integration tests. Make sure you have at least venom version 1.2.0.

Unit tests would also most likely be welcome for contribution with go native tests.

### Local Builds

Simply run the docker compose setup - `sudo docker compose up --build`.

You can navigate to the Vault UI locally at `http://localhost:8200` and use the root token value of `thisisatokenvalue` to login, as Vault is running in dev mode. It'll setup some initial settings for you with `vault-setup.sh.`
