package vault_mon

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	log "github.com/aarnaud/vault-pki-exporter/pkg/logger"
	"github.com/aarnaud/vault-pki-exporter/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

type PKI struct {
	path       string
	certs      map[string]*x509.Certificate
	crl        *pkix.CertificateList
	crlRawSize int
	vault      *vaultapi.Client
	certsmux   sync.Mutex
	crlmux     sync.Mutex
}

type PKIMon struct {
	pkis   map[string]*PKI
	vault  *vaultapi.Client
	mux    sync.Mutex
	Loaded bool
}

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

func (pki *PKI) loadCrl() (*pkix.CertificateList, error) {
	pki.crlmux.Lock()
	defer pki.crlmux.Unlock()
	secret, err := pki.vault.Logical().Read(fmt.Sprintf("%scert/crl", pki.path))
	if err != nil {
		return nil, err
	}
	secretCert := vault.SecretCertificate{}
	err = mapstructure.Decode(secret.Data, &secretCert)
	block, _ := pem.Decode([]byte([]byte(secretCert.Certificate)))
	pki.crlRawSize = len([]byte(secretCert.Certificate))
	// log.Infof("%q crl raw size %d", pki.path, pki.crlRawSize)

	crl, err := x509.ParseCRL(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load CRL for %s, error: %w", pki.path, err.Error())
	}
	pki.crl = crl
	// log.Infof("%q crl size %d", pki.path, len(crl.TBSCertList.RevokedCertificates))
	// log.Infof("%q crl raw size in tbscertlist %d", pki.path, len(crl.TBSCertList.Raw))

	return pki.crl, nil
}

func (pki *PKI) loadCerts() error {
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

	serialsList := vault.SecretList{}
	err = mapstructure.Decode(secret.Data, &serialsList)
	if err != nil {
		return err
	}

	for _, serial := range serialsList.Keys {
		secret, err := pki.vault.Logical().Read(fmt.Sprintf("%scert/%s", pki.path, serial))
		if err != nil {
			log.Errorf("failed to get certificate for %s%s, got error: %w", pki.path, serial, err.Error())
			continue
		}
		secretCert := vault.SecretCertificate{}
		err = mapstructure.Decode(secret.Data, &secretCert)
		block, _ := pem.Decode([]byte([]byte(secretCert.Certificate)))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Errorf("failed to load certificate for %s/%s, error: %w", pki.path, serial, err.Error())
			continue
		}

		// if already in map check the expiration
		if certInMap, ok := pki.certs[cert.Subject.CommonName]; ok && certInMap.NotAfter.Unix() < cert.NotAfter.Unix() {
			pki.certs[cert.Subject.CommonName] = cert
		}

		// if not in map add it if it's not expired
		if _, ok := pki.certs[cert.Subject.CommonName]; !ok && cert.NotAfter.Unix() > time.Now().Unix() {
			revoked, err := pki.certIsRevokedCRL(cert)
			if err != nil {
				log.Errorln(err)
			}
			if !revoked {
				pki.certs[cert.Subject.CommonName] = cert
			}

		}
	}

	return nil
}

func (pki *PKI) certIsRevokedCRL(cert *x509.Certificate) (bool, error) {
	crl, err := pki.loadCrl()
	if err != nil {
		return false, err
	}

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return true, nil
		}
	}
	return false, nil
}

func (pki *PKI) clearCerts() {
	pki.certsmux.Lock()
	pki.certs = make(map[string]*x509.Certificate)
	pki.certsmux.Unlock()
}

func (pki *PKI) GetCRL() *pkix.CertificateList {
	pki.crlmux.Lock()
	defer pki.crlmux.Unlock()
	return pki.crl
}

func (pki *PKI) GetCerts() map[string]*x509.Certificate {
	pki.certsmux.Lock()
	defer pki.certsmux.Unlock()
	return pki.certs
}
