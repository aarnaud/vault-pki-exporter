package vault_mon

import (
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

func PromWatchCerts(pkimon *PKIMon, interval time.Duration) {
	expiry := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_cert_expiry",
	}, labelNames)
	age := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_cert_age",
	}, labelNames)
	startdate := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_cert_startdate",
	}, labelNames)
	enddate := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_cert_enddate",
	}, labelNames)

	crl_expiry := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_crl_expiry",
	}, []string{"source"})
	crl_nextupdate := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_crl_nextupdate",
	}, []string{"source"})
	crl_byte_size := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_crl_byte_size",
		Help: "Size of raw certificate revocation list pem stored in vault",
	}, []string{"source"})
	crl_length := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_crl_length",
		Help: "Length of certificate revocation list",
	}, []string{"source"})
	go func() {
		for {
			pkis := pkimon.GetPKIs()
			expiry.Reset()
			age.Reset()
			startdate.Reset()
			enddate.Reset()
			crl_expiry.Reset()
			crl_nextupdate.Reset()
			now := time.Now()
			for pkiname, pki := range pkis {
				if crl := pki.GetCRL(); crl != nil {
					crl_expiry.WithLabelValues(pkiname).Set(float64(crl.TBSCertList.NextUpdate.Sub(now).Seconds()))
					crl_nextupdate.WithLabelValues(pkiname).Set(float64(crl.TBSCertList.NextUpdate.Unix()))
					crl_length.WithLabelValues(pkiname).Set(float64(len(crl.TBSCertList.RevokedCertificates)))
					crl_byte_size.WithLabelValues(pkiname).Set(float64(pki.crlRawSize))
				}
				for _, cert := range pki.GetCerts() {
					certlabels := getLabelValues(pkiname, cert)
					expiry.WithLabelValues(certlabels...).Set(float64(cert.NotAfter.Sub(now).Seconds()))
					age.WithLabelValues(certlabels...).Set(float64(now.Sub(cert.NotBefore).Seconds()))
					startdate.WithLabelValues(certlabels...).Set(float64(cert.NotBefore.Unix()))
					enddate.WithLabelValues(certlabels...).Set(float64(cert.NotAfter.Unix()))
				}
			}
			time.Sleep(interval)
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
