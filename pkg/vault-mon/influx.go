package vault_mon

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	influx "github.com/influxdata/influxdb1-client"
)

var hostname string

func InfluxWatchCerts(pkimon *PKIMon, interval time.Duration, loop bool) {
	hostname = os.Getenv("HOSTNAME")
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if loop {
		go func() {
			for {
				influxProcessData(pkimon)
				slog.Info("Sleeping after processing influx data", "interval", interval)
				time.Sleep(interval)
			}
		}()
	} else {
		// Wait for all PKI
		// TODO: use chan for pub/sub
		for !pkimon.Loaded {
			time.Sleep(time.Second)
		}
		influxProcessData(pkimon)
	}
}

func influxProcessData(pkimon *PKIMon) {
	for pkiname, pki := range pkimon.GetPKIs() {
		for _, crl := range pki.GetCRLs() {
			if crl != nil {
				printCrlInfluxPoint(pkiname, crl)
			}
		}
		for commonName, orgUnits := range pki.GetCerts() {
			for orgUnit, cert := range orgUnits {
				printCertificateInfluxPoint(pkiname, commonName, orgUnit, cert)
			}
		}
	}
}

func printCertificateInfluxPoint(pkiname, commonName, orgUnit string, cert *x509.Certificate) {
	now := time.Now()
	point := influx.Point{
		Measurement: "x509_cert",
		Tags: map[string]string{
			"host":                hostname,
			"source":              pkiname,
			"serial":              strings.ReplaceAll(fmt.Sprintf("% x", cert.SerialNumber.Bytes()), " ", "-"),
			"common_name":         commonName,
			"organization":        getEmptyStringIfEmpty(cert.Subject.Organization),
			"organizational_unit": orgUnit,
			"country":             getEmptyStringIfEmpty(cert.Subject.Country),
			"province":            getEmptyStringIfEmpty(cert.Subject.Province),
			"locality":            getEmptyStringIfEmpty(cert.Subject.Locality),
		},
		Fields: map[string]interface{}{
			"expiry":    int(cert.NotAfter.Sub(now).Seconds()),
			"age":       int(now.Sub(cert.NotBefore).Seconds()),
			"startdate": int(cert.NotBefore.Unix()),
			"enddate":   int(cert.NotAfter.Unix()),
		},
	}
	fmt.Println(point.MarshalString())
}

func printCrlInfluxPoint(pkiname string, crl *x509.RevocationList) {
	now := time.Now()
	point := influx.Point{
		Measurement: "x509_crl",
		Tags: map[string]string{
			"host":   hostname,
			"source": pkiname,
		},
		Fields: map[string]interface{}{
			"expiry":     int(crl.NextUpdate.Sub(now).Seconds()),
			"nextupdate": int(crl.NextUpdate.Unix()),
		},
	}
	fmt.Println(point.MarshalString())
}
