package vault_mon

import (
	"crypto/x509"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"strings"
	"time"
)

var labelNames = []string{
	"source",
	"serial",
	"common_name",
	"organization",
	"organizational_unit",
	"country",
	"province",
	"locality",
}

type PromMetrics struct {
	expiry    *prometheus.GaugeVec
	age       *prometheus.GaugeVec
	startdate *prometheus.GaugeVec
	enddate   *prometheus.GaugeVec
}

func PromWatchCerts(pkimon *PKIMon) {
	expiry := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509cert_expiry",
	}, labelNames)
	age := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509cert_age",
	}, labelNames)
	startdate := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509cert_startdate",
	}, labelNames)
	enddate := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509cert_enddate",
	}, labelNames)
	go func() {
		for {
			pkis := pkimon.GetPKIs()
			expiry.Reset()
			for pkiname, pki := range pkis {
				for _, cert := range pki.GetCerts() {
					now := time.Now()
					certlabels := getLabelValues(pkiname, cert)
					expiry.WithLabelValues(certlabels...).Set(float64(cert.NotAfter.Sub(now).Seconds()))
					age.WithLabelValues(certlabels...).Set(float64(now.Sub(cert.NotBefore).Seconds()))
					startdate.WithLabelValues(certlabels...).Set(float64(cert.NotBefore.Unix()))
					enddate.WithLabelValues(certlabels...).Set(float64(cert.NotAfter.Unix()))
				}
			}
			time.Sleep(time.Second)
		}
	}()

}

func getLabelValues(pkiname string, cert *x509.Certificate) []string {
	return []string{
		pkiname,
		strings.ReplaceAll(fmt.Sprintf("% x", cert.SerialNumber.Bytes()), " ", "-"),
		cert.Subject.CommonName,
		getEmptyStringIfEmpty(cert.Subject.Organization),
		getEmptyStringIfEmpty(cert.Subject.OrganizationalUnit),
		getEmptyStringIfEmpty(cert.Subject.Country),
		getEmptyStringIfEmpty(cert.Subject.Province),
		getEmptyStringIfEmpty(cert.Subject.Locality),
	}
}

func PromStartExporter(port int) {
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		log.Fatal(err)
	}
}
