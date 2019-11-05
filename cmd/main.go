package main

import (
	log "github.com/aarnaud/vault-pki-mon/pkg/logger"
	"github.com/aarnaud/vault-pki-mon/pkg/vault"
	vaultMon "github.com/aarnaud/vault-pki-mon/pkg/vault-mon"
)

func main() {

	cli := vault.ClientWrapper{}
	cli.Init()

	pkiMon := vaultMon.PKIMon{}
	err := pkiMon.Init(cli.Client)
	if err != nil {
		log.Errorln(err.Error())
	}

	pkiMon.Watch()

	//vaultMon.PromWatchCerts(&pkiMon)
	//vaultMon.PromStartExporter()

	select {}
}
