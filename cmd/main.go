package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aarnaud/vault-pki-exporter/pkg/logger"
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
		logger.SlogFatal("Could not bind verbose flag", "error", err)
	}

	flags.String("log-level", "info", "Set log level (options: info, warn, error, debug)")
	if err := viper.BindPFlag("log-level", flags.Lookup("log-level")); err != nil {
		logger.SlogFatal("Could not bind log-level flag", "error", err)
	}

	flags.BoolP("prometheus", "", false, "Enable prometheus exporter, default if nothing else")
	if err := viper.BindPFlag("prometheus", flags.Lookup("prometheus")); err != nil {
		logger.SlogFatal("Could not bind prometheus flag", "error", err)
	}

	flags.BoolP("influx", "", false, "Enable InfluxDB Line Protocol")
	if err := viper.BindPFlag("influx", flags.Lookup("influx")); err != nil {
		logger.SlogFatal("Could not bind influx flag", "error", err)
	}

	flags.Int("port", 9333, "Prometheus exporter HTTP port")
	if err := viper.BindPFlag("port", flags.Lookup("port")); err != nil {
		logger.SlogFatal("Could not bind port flag", "error", err)
	}

	flags.Duration("fetch-interval", time.Minute, "How many sec between fetch certs on vault")
	if err := viper.BindPFlag("fetch_interval", flags.Lookup("fetch-interval")); err != nil {
		logger.SlogFatal("Could not bind fetch-interval flag", "error", err)
	}

	flags.Duration("refresh-interval", time.Minute, "How many sec between metrics update")
	if err := viper.BindPFlag("refresh_interval", flags.Lookup("refresh-interval")); err != nil {
		logger.SlogFatal("Could not bind refresh-interval flag", "error", err)
	}

	flags.Float64("batch-size-percent", 1, "loadCerts batch size percentage, supports floats (e.g 0.0 - 100.0)")
	if err := viper.BindPFlag("batch_size_percent", flags.Lookup("batch-size-percent")); err != nil {
		logger.SlogFatal("Could not bind batch-size-percent flag", "error", err)
	}
}

func main() {
	cli.ParseFlags(os.Args[1:])

	// preserve deprecated verbose flag
	if viper.GetBool("verbose") {
		logger.Init("debug")
	} else {
		logger.Init(viper.GetString("log-level"))
	}

	// note mix of underscores and dashes
	slog.Info("CLI flag values", "fetch-interval", viper.GetDuration("fetch_interval"), "refresh-interval", viper.GetDuration("refresh_interval"), "batch-size-percent", viper.GetFloat64("batch_size_percent"))

	err := cli.Execute()
	if err != nil {
		logger.SlogFatal("CLI execution failed", "error", err)
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
