package logging

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger returns a structured JSON logger at the given level.
// Accepted levels: "debug", "info", "warn", "error". Defaults to "info".
func NewLogger(level string) *slog.Logger {
	var lvl slog.Level

	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	})

	return slog.New(handler)
}
