package main

import (
	"fmt"
	log "github.com/aarnaud/vault-pki-exporter/pkg/logger"
	"github.com/aarnaud/vault-pki-exporter/pkg/vault"
	vaultMon "github.com/aarnaud/vault-pki-exporter/pkg/vault-mon"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"time"
)

var version string
var cli = &cobra.Command{
	Run: func(cmd *cobra.Command, args []string) {
		entrypoint()
	},
}

var cliOptionVersion = &cobra.Command{
	Use:   "version",
	Short: "Print the version.",
	Long:  "The version of this program",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}

func init() {
	cli.AddCommand(cliOptionVersion)

	flags := cli.Flags()

	flags.BoolP("verbose", "v", false, "Enable verbose")
	if err := viper.BindPFlag("verbose", flags.Lookup("verbose")); err != nil {
		log.Fatal(err)
	}

	flags.BoolP("prometheus", "", false, "Enable prometheus exporter, default if nothing else")
	if err := viper.BindPFlag("prometheus", flags.Lookup("prometheus")); err != nil {
		log.Fatal(err)
	}

	flags.BoolP("influx", "", false, "Enable InfluxDB Line Protocol")
	if err := viper.BindPFlag("influx", flags.Lookup("influx")); err != nil {
		log.Fatal(err)
	}

	flags.Int("port", 9333, "Prometheus exporter HTTP port")
	if err := viper.BindPFlag("port", flags.Lookup("port")); err != nil {
		log.Fatal(err)
	}

	flags.Duration("fetch-interval", time.Minute, "How many sec between fetch certs on vault")
	if err := viper.BindPFlag("fetch_interval", flags.Lookup("fetch-interval")); err != nil {
		log.Fatal(err)
	}

	flags.Duration("refresh-interval", time.Minute, "How many sec between metrics update")
	if err := viper.BindPFlag("refresh_interval", flags.Lookup("refresh-interval")); err != nil {
		log.Fatal(err)
	}
}

func main() {
	err := cli.Execute()
	if err != nil {
		log.Fatal(err)
	}
}

func entrypoint() {

	vaultcli := vault.ClientWrapper{}
	vaultcli.Init()

	pkiMon := vaultMon.PKIMon{}
	err := pkiMon.Init(vaultcli.Client)
	if err != nil {
		log.Errorln(err.Error())
	}

	pkiMon.Watch(viper.GetDuration("fetch_interval"))

	if viper.GetBool("prometheus") || !viper.GetBool("influx") {
		log.Infoln("start prometheus exporter")
		vaultMon.PromWatchCerts(&pkiMon, viper.GetDuration("refresh_interval"))
		vaultMon.PromStartExporter(viper.GetInt("port"))
	}

	if viper.GetBool("influx") {
		vaultMon.InfluxWatchCerts(&pkiMon, viper.GetDuration("refresh_interval"), viper.GetBool("prometheus"))
	}
}
