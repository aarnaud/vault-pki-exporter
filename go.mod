module github.com/aarnaud/vault-pki-mon

go 1.13

require (
	github.com/hashicorp/vault-plugin-auth-jwt v0.5.2-0.20191010173058-65cf93bad3f2
	github.com/hashicorp/vault/api v1.0.5-0.20190814205728-e9c5cd8aca98
	github.com/influxdata/influxdb1-client v0.0.0-20190809212627-fc22c7df067e
	github.com/mitchellh/mapstructure v1.1.2
	github.com/prometheus/client_golang v1.2.1
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.5.0
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
)
