package vault_mon

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aarnaud/vault-pki-exporter/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

type PKI struct {
	path                string
	certs               map[string]map[string]*x509.Certificate
	crls                map[string]*x509.RevocationList
	crlRawSize          int
	expiredCertsCounter int
	vault               *vaultapi.Client
	certsmux            sync.Mutex
	crlmux              sync.Mutex
}

type PKIMon struct {
	pkis   map[string]*PKI
	vault  *vaultapi.Client
	mux    sync.Mutex
	Loaded bool
}

var loadCertsDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "x509_load_certs_duration_seconds",
	Help:    "Duration of loadCerts execution",
	Buckets: prometheus.ExponentialBuckets(1, 3, 10),
})

var loadCertsLimitDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "x509_load_certs_request_limit_gated_duration_seconds",
	Help:    "Duration of time spent throttled waiting to contact Vault during loadCerts execution",
	Buckets: prometheus.ExponentialBuckets(1, 3, 10),
})

func (mon *PKIMon) Init(vault *vaultapi.Client) error {
	mon.vault = vault
	mon.pkis = make(map[string]*PKI)
	return nil
}

func (mon *PKIMon) loadPKI() error {
	mon.mux.Lock()
	defer mon.mux.Unlock()
	secret, err := mon.vault.Logical().Read("sys/mounts")
	if err != nil {
		return err
	}
	mounts := map[string]*vaultapi.MountOutput{}
	err = mapstructure.Decode(secret.Data, &mounts)
	if err != nil {
		return err
	}

	for name, mount := range mounts {
		if mount.Type == "pki" {
			if _, ok := mon.pkis[name]; !ok {
				pki := PKI{path: name, vault: mon.vault, certs: make(map[string]map[string]*x509.Certificate)}
				mon.pkis[name] = &pki
				slog.Info("PKI loaded", "pki", pki.path)
			}
		}
	}
	return nil
}

func (mon *PKIMon) Watch(interval time.Duration) {
	slog.Info("Start watching PKI certs")

	go func() {
		for {
			slog.Info("Refresh PKI list")
			err := mon.loadPKI()
			if err != nil {
				slog.Error("Error loading PKI", "error", err)
			}
			for _, pki := range mon.pkis {
				slog.Info("Refresh PKI certificate", "pki", pki.path)
				pki.clearCerts()

				err = pki.loadCrl()
				if err != nil {
					slog.Error("Error loading CRL", "pki", pki.path, "error", err)
				}

				err := pki.loadCerts()
				if err != nil {
					slog.Error("Error loading certs", "pki", pki.path, "error", err)
				}

			}
			mon.Loaded = true
			slog.Info("Sleeping after refreshing PKI certs", "interval", interval)
			time.Sleep(interval)
		}
	}()
}

func (mon *PKIMon) GetPKIs() map[string]*PKI {
	mon.mux.Lock()
	defer mon.mux.Unlock()
	return mon.pkis
}

func (pki *PKI) loadCrl() error {
	pki.crlmux.Lock()
	defer pki.crlmux.Unlock()

	// List all issuers to get multiple CRLs per PKI engine
	issuers, err := pki.listIssuers()
	if err != nil {
		return err
	}

	if pki.crls == nil {
		pki.crls = make(map[string]*x509.RevocationList)
		slog.Warn("Initialized an empty certs list", "pki", pki.path)
	}

	for _, issuerRef := range issuers {
		crl, err := pki.loadCrlForIssuer(issuerRef)
		if err != nil {
			slog.Error("Failed to load CRL", "pki", pki.path, "issuer", issuerRef, "error", err)
		} else if crl == nil {
			slog.Error("CRL cannot be loaded", "pki", pki.path, "issuer", issuerRef)
		} else {
			pki.crls[issuerRef] = crl
		}
	}

	return nil
}

func (pki *PKI) listIssuers() ([]string, error) {

	// Request PKI engine Vault issuers
	secret, err := pki.vault.Logical().List(fmt.Sprintf("%s/issuers", pki.path))
	if err != nil {
		return nil, fmt.Errorf("error listing issuers: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	// The key under which issuers are listed might vary, so adjust "keys" accordingly
	issuerRefs, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse issuer list")
	}

	issuers := make([]string, len(issuerRefs))
	for i, ref := range issuerRefs {
		issuer, ok := ref.(string)
		if !ok {
			return nil, fmt.Errorf("invalid issuer reference type")
		}
		issuers[i] = issuer
	}

	return issuers, nil
}

func (pki *PKI) loadCrlForIssuer(issuerRef string) (*x509.RevocationList, error) {
	secret, err := pki.vault.Logical().Read(fmt.Sprintf("/%s/issuer/%s/crl", pki.path, issuerRef))
	if err != nil {
		return nil, fmt.Errorf("error finding CRL at /%s/issuer/%s/crl: %w", pki.path, issuerRef, err)
	}

	if secret == nil {
		return nil, fmt.Errorf("no secret found for issuer %s", issuerRef)
	}

	crlData, ok := secret.Data["crl"].(string)
	if !ok || crlData == "" {
		return nil, fmt.Errorf("CRL data missing or invalid for issuer %s", issuerRef)
	}

	block, _ := pem.Decode([]byte(crlData))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block for issuer %s", issuerRef)
	}

	pki.crlRawSize = len([]byte(crlData))

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing CRL for issuer %s: %w", issuerRef, err)
	}

	slog.Debug("Successfully loaded CRL", "pki", pki.path, "issuer", issuerRef)

	return crl, nil
}

func (pki *PKI) loadCerts() error {

	startTime := time.Now()
	pki.certsmux.Lock()
	defer pki.certsmux.Unlock()

	if pki.certs == nil {
		pki.certs = make(map[string]map[string]*x509.Certificate)
		slog.Warn("Initialized an empty certs list", "pki", pki.path)
	}

	secret, err := pki.vault.Logical().List(fmt.Sprintf("%scerts", pki.path))
	if err != nil {
		return err
	}
	if secret == nil || secret.Data == nil {
		// if path has no certs, exit straight away
		// before hitting a segfault
		return nil
	}

	serialsList := vault.SecretList{}
	err = mapstructure.Decode(secret.Data, &serialsList)
	if err != nil {
		return err
	}

	// reset expired certs to avoid counter creep
	pki.expiredCertsCounter = 0

	// determine batch size dynamically based on the length of serialsList.Keys
	batchSizePercentage := viper.GetFloat64("batch_size_percent")

	// use float divison and round
	batchSize := int(float64(len(serialsList.Keys)) * (batchSizePercentage / 100.0))
	if batchSize < 1 {
		batchSize = 1
	}

	requestLimit := rate.Limit(viper.GetFloat64("request_limit"))
	requestLimitBurst := viper.GetInt("request_limit_burst")

	// Special value for limiter that allows all events
	if requestLimit == 0 {
		requestLimit = rate.Inf
	}

	// If non-default value for requestLimit, but default requestLimitBurst,
	// set requestLimitBurst to requestLimit
	if requestLimit != rate.Inf && requestLimitBurst == 0 {
		requestLimitBurst = int(requestLimit)
	}

	limiter := rate.NewLimiter(requestLimit, requestLimitBurst)

	// gather CRLs to determine revoked certs
	revokedCerts := make(map[string]struct{})

	for _, crl := range pki.GetCRLs() {

		// gather revoked certs from the CRL so we can exclude their metrics later
		for _, revokedCert := range crl.RevokedCertificates {
			revokedCerts[revokedCert.SerialNumber.String()] = struct{}{}
		}
	}

	// loop in batches via waitgroups to make this much faster for large vault installations
	for i := 0; i < len(serialsList.Keys); i += batchSize {
		end := i + batchSize
		if end > len(serialsList.Keys) {
			end = len(serialsList.Keys)
		}
		batchKeys := serialsList.Keys[i:end]

		var wg sync.WaitGroup
		slog.Info("Processing batch of certs", "pki", pki.path, "batchsize", len(batchKeys), "total_size", len(serialsList.Keys))

		// add a mutex for protecting concurrent access to the certs map
		var certsMux sync.Mutex
		for _, serial := range batchKeys {
			wg.Add(1)
			go func(serial string) {
				defer wg.Done()

				waitStart := time.Now()
				err := limiter.Wait(context.Background())
				if err != nil {
					slog.Error("Error waiting for request limiter", "error", err)
					return
				}
				loadCertsLimitDuration.Observe(time.Since(waitStart).Seconds())

				secret, err := pki.vault.Logical().Read(fmt.Sprintf("%scert/%s", pki.path, serial))
				if err != nil || secret == nil || secret.Data == nil {
					slog.Error("Failed to get certificate", "pki", pki.path, "serial", serial, "error", err)
					return
				}

				secretCert := vault.SecretCertificate{}
				err = mapstructure.Decode(secret.Data, &secretCert)
				if err != nil {
					slog.Error("Failed to decode secret", "pki", pki.path, "serial", serial, "error", err)
					return
				}

				block, _ := pem.Decode([]byte(secretCert.Certificate))
				if block == nil {
					slog.Error("Failed to decode PEM block", "pki", pki.path, "serial", serial)
					return
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					slog.Error("Failed to load certificate", "pki", pki.path, "serial", serial, "error", err)
					return
				}

				commonName := cert.Subject.CommonName
				orgUnit := ""
				// define certs by their commonName and *Subject* (not issuer) OU
				if len(cert.Subject.OrganizationalUnit) > 0 {
					orgUnit = cert.Subject.OrganizationalUnit[0]
				}

				certsMux.Lock()
				if _, exists := pki.certs[commonName]; !exists {
					pki.certs[commonName] = make(map[string]*x509.Certificate)
				}

				// if cert is revoked, never add it to the map
				if _, isRevoked := revokedCerts[cert.SerialNumber.String()]; isRevoked {
					slog.Debug("Cert rejected as it is revoked", "pki", pki.path, "serial", serial, "common_name", cert.Subject.CommonName, "organizational_unit", cert.Subject.OrganizationalUnit)
					return
				}

				// if cert is in map already or the new cert has a *later* expiration date, update map
				// handles renewal of existing cert smoothly
				if existingCert, ok := pki.certs[commonName][orgUnit]; !ok || existingCert.NotAfter.Before(cert.NotAfter) {
					pki.certs[commonName][orgUnit] = cert
					slog.Debug("Updated certificate in map", "pki", pki.path, "serial", serial, "common_name", cert.Subject.CommonName, "organizational_unit", cert.Subject.OrganizationalUnit)
				}

				if cert.NotAfter.Before(time.Now()) {
					pki.expiredCertsCounter++
					slog.Debug("Cert rejected as it is expired", "pki", pki.path, "serial", serial, "common_name", cert.Subject.CommonName, "organizational_unit", cert.Subject.OrganizationalUnit)
					// we still want metrics if a cert is expired so don't return
				}

				certsMux.Unlock()
			}(serial)
		}
		wg.Wait()
	}
	loadCertsDuration.Observe(time.Since(startTime).Seconds())
	return nil
}

func (pki *PKI) clearCerts() {
	pki.certsmux.Lock()
	pki.certs = make(map[string]map[string]*x509.Certificate)
	pki.certsmux.Unlock()
}

func (pki *PKI) GetCRLs() map[string]*x509.RevocationList {
	pki.crlmux.Lock()
	defer pki.crlmux.Unlock()
	return pki.crls
}

func (pki *PKI) GetCerts() map[string]map[string]*x509.Certificate {
	pki.certsmux.Lock()
	defer pki.certsmux.Unlock()
	return pki.certs
}
