// Command release-sign signs a Vectis release artifact with the release Ed25519
// key, or generates a keypair. It is used by .github/workflows/release.yml to
// produce the `.ed25519` signature files that running installs verify via
// internal/releasesign (audit E-H2/E-H3).
//
// Signing:
//
//	VECTIS_RELEASE_SIGNING_KEY=<base64 64-byte ed25519 private key> \
//	  release-sign vectis-linux-amd64 > vectis-linux-amd64.ed25519
//
// The private key is read from the environment (never a process arg, so it stays
// out of CI logs and `ps`). The signature is written to stdout as standard
// base64 of the raw 64-byte Ed25519 signature.
//
// Key generation (one-off, run in a secure environment):
//
//	release-sign -genkey
//
// prints the base64 private key (store as the VECTIS_RELEASE_SIGNING_KEY GitHub
// Actions secret) and the base64 public key (paste into
// internal/releasesign.PublicKeyB64).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
)

const keyEnv = "VECTIS_RELEASE_SIGNING_KEY"

func main() {
	genkey := flag.Bool("genkey", false, "generate a new Ed25519 release keypair and print it")
	flag.Parse()

	if *genkey {
		if err := generate(); err != nil {
			fatal(err)
		}
		return
	}

	if flag.NArg() != 1 {
		fatal(fmt.Errorf("usage: %s <file>  (with $%s set)  |  %s -genkey", os.Args[0], keyEnv, os.Args[0]))
	}
	if err := sign(flag.Arg(0)); err != nil {
		fatal(err)
	}
}

func generate() error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	fmt.Printf("# %s (PRIVATE — store as a GitHub Actions secret, never commit):\n%s\n\n",
		keyEnv, base64.StdEncoding.EncodeToString(priv))
	fmt.Printf("# releasesign.PublicKeyB64 (PUBLIC — paste into internal/releasesign/releasesign.go):\n%s\n",
		base64.StdEncoding.EncodeToString(pub))
	return nil
}

func sign(path string) error {
	keyB64 := strings.TrimSpace(os.Getenv(keyEnv))
	if keyB64 == "" {
		return fmt.Errorf("$%s is not set", keyEnv)
	}
	priv, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return fmt.Errorf("decode $%s: %w", keyEnv, err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("$%s wrong size: %d (want %d)", keyEnv, len(priv), ed25519.PrivateKeySize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(priv), data)
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "release-sign:", err)
	os.Exit(1)
}
