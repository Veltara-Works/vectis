package database

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds the parameters needed to connect to Postgres.
type Config struct {
	Host     string
	Port     int
	Name     string
	User     string
	Password string
}

// DSN returns a PostgreSQL connection URI. Every component is
// percent-encoded, so a password containing URI delimiters (@ # / ? % or a
// space) reaches the server intact. pgx 5.11 parses URIs exactly as libpq
// does (the first "@" ends the userinfo, "#" is data), so an unescaped
// password that net/url used to tolerate would now fail to connect.
func (c Config) DSN() string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.User, c.Password),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:     "/" + c.Name,
		RawQuery: "sslmode=disable",
	}
	return u.String()
}

// NewPool creates a pgxpool connection pool with sensible defaults.
func NewPool(ctx context.Context, cfg Config, logger *slog.Logger) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("parse database DSN: %w", err)
	}

	poolCfg.MaxConns = 20
	poolCfg.MinConns = 2
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	logger.Info("database connection pool established",
		"host", cfg.Host,
		"port", cfg.Port,
		"database", cfg.Name,
		"user", cfg.User,
	)

	return pool, nil
}

// ConfigFromSecrets builds a database.Config from the secrets config values.
func ConfigFromSecrets(host string, port int, name, user, password string) Config {
	return Config{
		Host:     host,
		Port:     port,
		Name:     name,
		User:     user,
		Password: password,
	}
}
