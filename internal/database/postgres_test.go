package database

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Installer-generated credentials are hex, so their DSN must be byte-for-byte
// what the old fmt.Sprintf form produced: escaping changes nothing for them.
func TestDSNUnchangedForHexPassword(t *testing.T) {
	c := Config{Host: "postgres", Port: 5432, Name: "vectis", User: "vectis_api", Password: "0123456789abcdef0123456789abcdef"}
	want := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", c.User, c.Password, c.Host, c.Port, c.Name)
	if got := c.DSN(); got != want {
		t.Fatalf("DSN() = %q, want %q", got, want)
	}
}

// pgx 5.11 parses URIs the way libpq does: the first "@" ends the userinfo,
// "#" is data, malformed "%" escapes are errors and edge spaces are trimmed.
// Every password must survive both pgx and the net/url parse that
// golang-migrate's pgx5 driver does first.
func TestDSNRoundTripsAwkwardPasswords(t *testing.T) {
	passwords := []string{
		"0123456789abcdef",
		"p@ss@word",
		"has#hash",
		"slash/and?query",
		"percent%zz%41",
		"plus+sign",
		" edge spaces ",
		"colon:in:it",
		`back\slash'quote"`,
		"üñíçødé",
	}
	for _, pw := range passwords {
		t.Run(pw, func(t *testing.T) {
			c := Config{Host: "postgres", Port: 5432, Name: "vectis", User: "vectis_api", Password: pw}
			dsn := c.DSN()

			cfg, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatalf("pgxpool.ParseConfig: %v", err)
			}
			cc := cfg.ConnConfig
			if cc.Password != pw || cc.User != c.User || cc.Host != c.Host || cc.Port != uint16(c.Port) || cc.Database != c.Name {
				t.Fatalf("parsed user=%q pw=%q host=%q port=%d db=%q", cc.User, cc.Password, cc.Host, cc.Port, cc.Database)
			}

			u, err := url.Parse("pgx5" + dsn[len("postgres"):])
			if err != nil {
				t.Fatalf("url.Parse (migrate path): %v", err)
			}
			if got, _ := u.User.Password(); got != pw {
				t.Fatalf("migrate path password = %q, want %q", got, pw)
			}
		})
	}
}

func TestDSNBracketsIPv6Host(t *testing.T) {
	c := Config{Host: "::1", Port: 5432, Name: "vectis", User: "u", Password: "p"}
	cfg, err := pgxpool.ParseConfig(c.DSN())
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig(%q): %v", c.DSN(), err)
	}
	if cfg.ConnConfig.Host != "::1" {
		t.Fatalf("host = %q, want ::1", cfg.ConnConfig.Host)
	}
}
