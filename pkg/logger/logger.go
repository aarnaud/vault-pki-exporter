package logger

import (
	"log/slog"
	"os"
)

// Initialize default logger
func Init(level string) {
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
	slog.Info("Logger initialized", "level", level)
}

// SlogFatal mimics log.Fatal but wrapped in slog
func SlogFatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
