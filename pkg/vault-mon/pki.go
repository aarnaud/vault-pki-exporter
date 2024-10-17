package vault_mon

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	log "github.com/aarnaud/vault-pki-exporter/pkg/logger"
	"github.com/aarnaud/vault-pki-exporter/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spf13/viper"
)

type PKI struct {
	path                string
	certs               map[string]*x509.Certificate
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
				pki := PKI{path: name, vault: mon.vault}
				mon.pkis[name] = &pki
				log.Infof("%s loaded", pki.path)
			}
		}
	}
	return nil
}

func (mon *PKIMon) Watch(interval time.Duration) {
	log.Infoln("Start watching pki certs")

	go func() {
		for {
			log.Infoln("Refresh PKI list")
			err := mon.loadPKI()
			if err != nil {
				log.Errorln(err)
			}
			for _, pki := range mon.pkis {
				log.Infof("Refresh PKI certificate for %s", pki.path)
				pki.clearCerts()

				err := pki.loadCerts()
				if err != nil {
					log.Errorln(err)
				}

				err = pki.loadCrl()
				if err != nil {
					log.Errorln(err)
				}
			}
			mon.Loaded = true
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
		log.Warningln("init an empty certs list")
	}

	for _, issuerRef := range issuers {
		crl, err := pki.loadCrlForIssuer(issuerRef)
		if err != nil || crl == nil {
			log.Errorf("loadCrl() failed to load CRL for issuer %s, error: %v", issuerRef, err)
		} else {
			pki.crls[issuerRef] = crl
		}
	}

	return nil
}

func (pki *PKI) listIssuers() ([]string, error) {
	// Define the path where the issuers are listed in your Vault setup
	// This path might be different based on your Vault configuration

	// Make a read request to Vault
	secret, err := pki.vault.Logical().List(fmt.Sprintf("%s/issuers", pki.path))
	if err != nil {
		return nil, fmt.Errorf("error listing issuers: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return []string{}, nil
	}

	// Extract the list of issuers from the response
	// The key under which issuers Ware listed might vary, so adjust "keys" accordingly
	issuerRefs, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse issuer list")
	}

	// Convert issuer references to a slice of strings
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
		log.Errorf("No secret found for issuer %s", issuerRef)
		return nil, fmt.Errorf("no secret found for issuer %s", issuerRef)
	}

	log.Infof("Issuer: %s, Secret Data: %v", issuerRef, secret.Data)

	crlData, ok := secret.Data["crl"].(string)
	if !ok || crlData == "" {
		log.Errorf("CRL data missing or invalid for issuer %s", issuerRef)
		return nil, fmt.Errorf("crl data missing or invalid for issuer %s", issuerRef)
	}

	log.Infof("Issuer: %s, Raw CRL Data: %s", issuerRef, crlData)

	block, _ := pem.Decode([]byte(crlData))
	if block == nil {
		log.Errorf("Failed to parse PEM block for issuer %s. Raw PEM data: %s", issuerRef, crlData)
		return nil, fmt.Errorf("failed to parse PEM block for issuer %s", issuerRef)
	}

	pki.crlRawSize = len([]byte(crlData))

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		log.Errorf("Error parsing CRL for issuer %s: %v", issuerRef, err)
		return nil, fmt.Errorf("error parsing CRL for issuer %s: %w", issuerRef, err)
	}

	log.Infof("Successfully loaded CRL for issuer %s", issuerRef)

	return crl, nil
}

func (pki *PKI) loadCerts() error {

	startTime := time.Now()
	pki.certsmux.Lock()
	defer pki.certsmux.Unlock()

	if pki.certs == nil {
		pki.certs = make(map[string]*x509.Certificate)
		log.Warningln("init an empty certs list")
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

	// loop in batches via waitgroups to make this much faster for large vault installations
	for i := 0; i < len(serialsList.Keys); i += batchSize {
		end := i + batchSize
		if end > len(serialsList.Keys) {
			end = len(serialsList.Keys)
		}
		batchKeys := serialsList.Keys[i:end]

		var wg sync.WaitGroup
		if viper.GetBool("verbose") {
			log.WithField("batchsize", len(batchKeys)).Infof("processing batch of certs in loadCerts")
		}

		// add a mutex for protecting concurrent access to the certs map
		var certsMux sync.Mutex
		for _, serial := range batchKeys {
			wg.Add(1)
			go func(serial string) {
				defer wg.Done()

				secret, err := pki.vault.Logical().Read(fmt.Sprintf("%scert/%s", pki.path, serial))
				if err != nil || secret == nil || secret.Data == nil {
					log.Errorf("failed to get certificate for %s%s, got error: %v", pki.path, serial, err)
					return
				}

				secretCert := vault.SecretCertificate{}
				err = mapstructure.Decode(secret.Data, &secretCert)
				if err != nil {
					log.Errorf("failed to decode secret for %s/%s, error: %v", pki.path, serial, err)
					return
				}

				block, _ := pem.Decode([]byte([]byte(secretCert.Certificate)))
				if block == nil {
					log.Errorf("failed to decode PEM block for %s/%s", pki.path, serial)
					return
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					log.Errorf("failed to load certificate for %s/%s, error: %v", pki.path, serial, err)
					return
				}

				certsMux.Lock()
				// if already in map check the expiration
				if certInMap, ok := pki.certs[cert.Subject.CommonName]; ok && certInMap.NotAfter.Unix() < cert.NotAfter.Unix() {
					pki.certs[cert.Subject.CommonName] = cert
				}

				if cert.NotAfter.Unix() < time.Now().Unix() {
					pki.expiredCertsCounter++
				}

				if _, ok := pki.certs[cert.Subject.CommonName]; !ok && cert.NotAfter.Unix() > time.Now().Unix() {
					pki.certs[cert.Subject.CommonName] = cert
					if err != nil {
						log.Errorln(err)
					}
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
	pki.certs = make(map[string]*x509.Certificate)
	pki.certsmux.Unlock()
}

func (pki *PKI) GetCRLs() map[string]*x509.RevocationList {
	pki.crlmux.Lock()
	defer pki.crlmux.Unlock()
	return pki.crls
}

func (pki *PKI) GetCerts() map[string]*x509.Certificate {
	pki.certsmux.Lock()
	defer pki.certsmux.Unlock()
	return pki.certs
}
