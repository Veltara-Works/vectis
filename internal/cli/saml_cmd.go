package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var samlCmd = &cobra.Command{
	Use:   "saml",
	Short: "SAML 2.0 SSO commands (Enterprise)",
}

var samlInitSPEntityID string

var samlInitSPCmd = &cobra.Command{
	Use:   "init-sp",
	Short: "Generate a Service Provider keypair for SAML SSO",
	Long: `Generates a self-signed RSA keypair for this install's SAML Service
Provider identity and prints a ready-to-paste secrets.yaml snippet.

The SP certificate is published in your SP metadata (which you hand to the IdP);
the private key signs AuthnRequests. Run this once per install, paste the output
under a top-level "saml:" block in /etc/vectis/secrets.yaml, then add your
providers and re-run "vectis config apply".`,
	RunE: runSAMLInitSP,
}

func runSAMLInitSP(cmd *cobra.Command, args []string) error {
	if samlInitSPEntityID == "" {
		return fmt.Errorf("--entity-id is required")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: samlInitSPEntityID},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().AddDate(10, 0, 0), // SP certs are long-lived; rotate by re-running.
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	indent := func(s string) string {
		return "    " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n    ")
	}

	fmt.Println("# Paste this under a top-level `saml:` block in /etc/vectis/secrets.yaml,")
	fmt.Println("# then add your IdP providers and run `vectis config apply`.")
	fmt.Println("saml:")
	fmt.Printf("  sp_entity_id: %q\n", samlInitSPEntityID)
	fmt.Println("  sp_private_key: |")
	fmt.Println(indent(string(keyPEM)))
	fmt.Println("  sp_certificate: |")
	fmt.Println(indent(string(certPEM)))
	fmt.Println("  providers:")
	fmt.Println("    # okta:")
	fmt.Println("    #   enabled: true")
	fmt.Println("    #   idp_metadata_url: \"https://YOUR-IDP/app/XXXX/sso/saml/metadata\"")
	fmt.Println("    #   email_attr: \"email\"   # optional; default \"email\"")
	return nil
}

func init() {
	samlInitSPCmd.Flags().StringVar(&samlInitSPEntityID, "entity-id", "",
		"SP entityID, e.g. https://mail.example.com/saml/metadata (required)")
	_ = samlInitSPCmd.MarkFlagRequired("entity-id")
	samlCmd.AddCommand(samlInitSPCmd)
	RootCmd.AddCommand(samlCmd)
}
