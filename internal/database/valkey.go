package database

import (
	"fmt"
	"log/slog"

	"github.com/valkey-io/valkey-go"
)

// ValkeyConfig holds connection parameters for Valkey.
type ValkeyConfig struct {
	Host     string
	Port     int
	Password string
}

// NewValkeyClient creates a Valkey client connection.
func NewValkeyClient(cfg ValkeyConfig, logger *slog.Logger) (valkey.Client, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{addr},
		Password:    cfg.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("create valkey client: %w", err)
	}

	logger.Info("valkey client connected", "host", cfg.Host, "port", cfg.Port)
	return client, nil
}
