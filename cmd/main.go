package main

import (
	"github.com/aarnaud/vault-pki-mon/pkg/vault"
)

func main() {

	cli := vault.ClientWrapper{}
	cli.Init()
	cli.Client.Logical().List("")

	select {}
}
