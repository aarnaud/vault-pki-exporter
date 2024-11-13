package vault_mon

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/aarnaud/vault-pki-exporter/pkg/logger"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

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
	certcount := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_cert_count",
		Help: "Total count of non-expired certificates including revoked certificates",
	}, []string{"source"})
	expired_cert_count := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_expired_cert_count",
		Help: "Total count of expired certificates including revoked certificates",
	}, []string{"source"})
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
	promWatchCertsDuration := promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "x509_watch_certs_duration_seconds",
		Help:    "Duration of promWatchCerts execution",
		Buckets: prometheus.ExponentialBuckets(0.0001, 4, 10),
	})
	go func() {
		for {
			startTime := time.Now()
			pkis := pkimon.GetPKIs()
			now := time.Now()
			revokedCerts := make(map[string]struct{})

			for pkiname, pki := range pkis {
				if crl := pki.GetCRL(); crl != nil {
					crl_expiry.WithLabelValues(pkiname).Set(float64(crl.TBSCertList.NextUpdate.Sub(now).Seconds()))
					crl_nextupdate.WithLabelValues(pkiname).Set(float64(crl.TBSCertList.NextUpdate.Unix()))
					crl_length.WithLabelValues(pkiname).Set(float64(len(crl.TBSCertList.RevokedCertificates)))
					crl_byte_size.WithLabelValues(pkiname).Set(float64(pki.crlRawSize))
					// gather revoked certs from the CRL so we can exclude their metrics later
					for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
						revokedCerts[revokedCert.SerialNumber.String()] = struct{}{}
					}
				}
				for _, cert := range pki.GetCerts() {

					certlabels := getLabelValues(pkiname, cert)

					if viper.GetBool("verbose") {
						log.WithFields(logrus.Fields{
							"organizational_unit": cert.Issuer.OrganizationalUnit,
							"serial_number":       cert.SerialNumber.String(),
							"common_name":         cert.Subject.CommonName,
							"organization":        cert.Subject.Organization,
							"not_before":          cert.NotBefore,
							"not_after":           cert.NotAfter,
						}).Infof("cert found")
					}

					if _, isRevoked := revokedCerts[cert.SerialNumber.String()]; isRevoked {
						// in case we have prior existing metrics, clear them for revoked certs
						// seems fine to run in case the metrics don't exist or are already deleted too
						expiry.DeleteLabelValues(certlabels...)
						age.DeleteLabelValues(certlabels...)
						startdate.DeleteLabelValues(certlabels...)
						enddate.DeleteLabelValues(certlabels...)

						if viper.GetBool("verbose") {
							log.WithField("common_name", cert.Subject.CommonName).Infof("cert found to be revoked")
						}

						continue
					}

					expiry.WithLabelValues(certlabels...).Set(float64(cert.NotAfter.Sub(now).Seconds()))
					age.WithLabelValues(certlabels...).Set(float64(now.Sub(cert.NotBefore).Seconds()))
					startdate.WithLabelValues(certlabels...).Set(float64(cert.NotBefore.Unix()))
					enddate.WithLabelValues(certlabels...).Set(float64(cert.NotAfter.Unix()))

				}
				certcount.WithLabelValues(pkiname).Set(float64(len(pki.certs)))
				expired_cert_count.WithLabelValues(pkiname).Set(float64(pki.expiredCertsCounter))
			}
			promWatchCertsDuration.Observe(time.Since(startTime).Seconds())
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
