package vault_mon

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	influx "github.com/influxdata/influxdb1-client"
	"os"
	"strings"
	"time"
)

var hostname string

func InfluxWatchCerts(pkimon *PKIMon) {
	hostname, _ = os.Hostname()
	go func() {
		for {
			for pkiname, pki := range pkimon.GetPKIs() {
				if crl := pki.GetCRL(); crl != nil {
					printCrlInfluxPoint(pkiname, crl)
				}
				for _, cert := range pki.GetCerts() {
					printCertificateInfluxPoint(pkiname, cert)
				}
			}
			time.Sleep(time.Second)
		}
	}()
}

func printCertificateInfluxPoint(pkiname string, cert *x509.Certificate) {
	now := time.Now()
	point := influx.Point{
		Measurement: "x509cert",
		Tags: map[string]string{
			"host":                hostname,
			"source":              pkiname,
			"serial":              strings.ReplaceAll(fmt.Sprintf("% x", cert.SerialNumber.Bytes()), " ", "-"),
			"common_name":         cert.Subject.CommonName,
			"organization":        getEmptyStringIfEmpty(cert.Subject.Organization),
			"organizational_unit": getEmptyStringIfEmpty(cert.Subject.OrganizationalUnit),
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
		Time:      time.Now(),
		Precision: "s",
	}
	fmt.Println(point.MarshalString())
}

func printCrlInfluxPoint(pkiname string, crl *pkix.CertificateList) {
	now := time.Now()
	point := influx.Point{
		Measurement: "x509crl",
		Tags: map[string]string{
			"host":   hostname,
			"source": pkiname,
		},
		Fields: map[string]interface{}{
			"expiry":     int(crl.TBSCertList.NextUpdate.Sub(now).Seconds()),
			"nextupdate": int(crl.TBSCertList.NextUpdate.Unix()),
		},
		Time:      time.Now(),
		Precision: "s",
	}
	fmt.Println(point.MarshalString())
}
