package vault_mon

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aarnaud/vault-pki-exporter/pkg/logger"
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
	}, []string{"source", "issuer"})
	crl_nextupdate := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_crl_nextupdate",
	}, []string{"source", "issuer"})
	crl_byte_size := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_crl_byte_size",
		Help: "Size of raw certificate revocation list pem stored in vault",
	}, []string{"source", "issuer"})
	crl_length := promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "x509_crl_length",
		Help: "Length of certificate revocation list",
	}, []string{"source", "issuer"})
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

			slog.Debug("Starting new PromWatchCerts loop", "interval_seconds", interval.Seconds(), "pkis_count", len(pkis))

			for pkiname, pki := range pkis {
				slog.Info("Processing PKI", "pki", pkiname)

				for _, crl := range pki.GetCRLs() {
					if crl != nil {
						issuer := crl.Issuer.CommonName

						crl_expiry.WithLabelValues(pkiname, issuer).Set(float64(crl.NextUpdate.Sub(now).Seconds()))
						crl_nextupdate.WithLabelValues(pkiname, issuer).Set(float64(crl.NextUpdate.Unix()))
						crl_length.WithLabelValues(pkiname, issuer).Set(float64(len(crl.RevokedCertificates)))
						crl_byte_size.WithLabelValues(pkiname, issuer).Set(float64(pki.crlRawSize))

						slog.Debug("Updated CRL metrics", "pki", pkiname, "issuer", issuer, "next_update", crl.NextUpdate)

						// gather revoked certs from the CRL so we can exclude their metrics later
						for _, revokedCert := range crl.RevokedCertificates {
							revokedCerts[revokedCert.SerialNumber.String()] = struct{}{}
						}
					}
				}

				for _, orgUnits := range pki.GetCerts() {
					for _, cert := range orgUnits {

						certlabels := getLabelValues(pkiname, cert)

						if _, isRevoked := revokedCerts[cert.SerialNumber.String()]; isRevoked {
							// in case we have prior existing metrics, clear them for revoked certs
							// seems fine to run in case the metrics don't exist or are already deleted too
							expiry.DeleteLabelValues(certlabels...)
							age.DeleteLabelValues(certlabels...)
							startdate.DeleteLabelValues(certlabels...)
							enddate.DeleteLabelValues(certlabels...)

							slog.Debug("Cleared metrics for revoked certificate", "pki", pkiname, "serial", cert.SerialNumber, "common_name", cert.Subject.CommonName, "organizational_unit", cert.Subject.OrganizationalUnit)

							continue
						}

						expiry.WithLabelValues(certlabels...).Set(float64(cert.NotAfter.Sub(now).Seconds()))
						age.WithLabelValues(certlabels...).Set(float64(now.Sub(cert.NotBefore).Seconds()))
						startdate.WithLabelValues(certlabels...).Set(float64(cert.NotBefore.Unix()))
						enddate.WithLabelValues(certlabels...).Set(float64(cert.NotAfter.Unix()))

						slog.Debug("Updated certificate metrics", "pki", pkiname, "serial", cert.SerialNumber, "common_name", cert.Subject.CommonName, "organizational_unit", cert.Subject.OrganizationalUnit)
					}
					certcount.WithLabelValues(pkiname).Set(float64(len(pki.certs)))
					expired_cert_count.WithLabelValues(pkiname).Set(float64(pki.expiredCertsCounter))

					slog.Info("PKI metrics updated", "pki", pkiname, "total_certs", len(pki.certs), "expired_certs", pki.expiredCertsCounter)
				}

				duration := time.Since(startTime).Seconds()
				promWatchCertsDuration.Observe(duration)
				slog.Info("PromWatchCerts loop completed", "duration_seconds", duration, "pkis_processed", len(pkis))
				time.Sleep(interval)
			}
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
	slog.Info("Starting Prometheus exporter", "port", port)
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		logger.SlogFatal("Failed to start Prometheus exporter", "error", err)
	}
}
