package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/aarnaud/vault-pki-exporter/pkg/vault"
	vaultMon "github.com/aarnaud/vault-pki-exporter/pkg/vault-mon"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	flags.String("log-level", "info", "Set log level (options: info, warn, error, debug)")
	if err := viper.BindPFlag("log-level", flags.Lookup("log-level")); err != nil {
		log.Fatal("Could not set log level:", err)
	}

	flags.BoolP("prometheus", "", false, "Enable prometheus exporter, default if nothing else")
	if err := viper.BindPFlag("prometheus", flags.Lookup("prometheus")); err != nil {
		log.Fatal("Could not bind prometheus flag:", err)
	}

	flags.BoolP("influx", "", false, "Enable InfluxDB Line Protocol")
	if err := viper.BindPFlag("influx", flags.Lookup("influx")); err != nil {
		log.Fatal("Could not bind influx flag:", err)
	}

	flags.Int("port", 9333, "Prometheus exporter HTTP port")
	if err := viper.BindPFlag("port", flags.Lookup("port")); err != nil {
		log.Fatal("Could not bind port flag:", err)
	}

	flags.Duration("fetch-interval", time.Minute, "How many sec between fetch certs on vault")
	if err := viper.BindPFlag("fetch_interval", flags.Lookup("fetch-interval")); err != nil {
		log.Fatal("Could not bind fetch-interval flag:", err)
	}

	flags.Duration("refresh-interval", time.Minute, "How many sec between metrics update")
	if err := viper.BindPFlag("refresh_interval", flags.Lookup("refresh-interval")); err != nil {
		log.Fatal("Could not bind refresh-interval flag:", err)
	}

	flags.Float64("batch-size-percent", 1, "loadCerts batch size percentage, supports floats (e.g 0.0 - 100.0)")
	if err := viper.BindPFlag("batch_size_percent", flags.Lookup("batch-size-percent")); err != nil {
		log.Fatal("Could not bind batch-size-percent flag:", err)
	}

	flags.Float64("request-limit", 0.0, "Token-bucket limiter for number of requests per second to Vault when fetching certs (0 = disabled)")
	if err := viper.BindPFlag("request_limit", flags.Lookup("request-limit")); err != nil {
		log.Fatal(err)
	}

	flags.Int("request-limit-burst", 0, "Token-bucket burst limit for number of requests per second to Vault when fetching certs (0 = match 'request-limit' value)")
	if err := viper.BindPFlag("request_limit_burst", flags.Lookup("request-limit-burst")); err != nil {
		log.Fatal(err)
	}
}

func main() {
	cli.ParseFlags(os.Args[1:])

	// preserve deprecated verbose flag
	if viper.GetBool("verbose") {
		setLogLevel("debug")
	} else {
		setLogLevel(viper.GetString("log-level"))
		slog.Info("Log level initialized", "log-level", viper.GetString("log-level"))
	}

	// note mix of underscores and dashes
	slog.Info("CLI flag values", "fetch-interval", viper.GetDuration("fetch_interval"), "refresh-interval", viper.GetDuration("refresh_interval"), "batch-size-percent", viper.GetFloat64("batch_size_percent"), "request-limit", viper.GetFloat64("request_limit"), "request-limit-burst", viper.GetInt("request_limit_burst") )

	err := cli.Execute()
	if err != nil {
		log.Fatal("CLI execution failed:", err)
	}
}

func entrypoint() {

	vaultcli := vault.ClientWrapper{}
	vaultcli.Init()

	pkiMon := vaultMon.PKIMon{}
	err := pkiMon.Init(vaultcli.Client)
	if err != nil {
		slog.Error("PKIMon initialization failed", "error", err)
	}

	pkiMon.Watch(viper.GetDuration("fetch_interval"))

	if viper.GetBool("prometheus") || !viper.GetBool("influx") {
		slog.Info("start prometheus exporter")
		vaultMon.PromWatchCerts(&pkiMon, viper.GetDuration("refresh_interval"))
		vaultMon.PromStartExporter(viper.GetInt("port"))
	}

	if viper.GetBool("influx") {
		vaultMon.InfluxWatchCerts(&pkiMon, viper.GetDuration("refresh_interval"), viper.GetBool("prometheus"))
	}
}

// https://pkg.go.dev/log/slog#example-SetLogLoggerLevel-Log
func setLogLevel(level string) {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slogLevel})
	slog.SetDefault(slog.New(handler))
}
