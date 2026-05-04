package branding

import "testing"

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"all empty (clear-to-defaults)", Config{}, false},
		{"valid hex 6", Config{PrimaryColor: "#3b82f6"}, false},
		{"valid hex 3", Config{PrimaryColor: "#abc"}, false},
		{"valid hex 8 (alpha)", Config{PrimaryColor: "#3b82f6ff"}, false},
		{"invalid hex (no #)", Config{PrimaryColor: "3b82f6"}, true},
		{"invalid hex (4 chars)", Config{PrimaryColor: "#abcd"}, true},
		{"valid https url", Config{LogoURL: "https://example.com/logo.svg"}, false},
		{"valid /assets path", Config{LogoURL: "/assets/logo.svg"}, false},
		{"reject http://", Config{LogoURL: "http://example.com/logo.svg"}, true},
		{"reject javascript:", Config{LogoURL: "javascript:alert(1)"}, true},
		{"reject data:", Config{LogoURL: "data:image/svg+xml,foo"}, true},
		{"reject relative path", Config{LogoURL: "logo.svg"}, true},
		{"product name at 64 ok", Config{ProductName: string(make([]byte, 64))}, false},
		{"product name >64 rejected", Config{ProductName: string(make([]byte, 65))}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestEffectiveFillsDefaults(t *testing.T) {
	cfg := Config{}
	eff := cfg.Effective()
	if eff.ProductName != DefaultProductName {
		t.Errorf("ProductName: want %q, got %q", DefaultProductName, eff.ProductName)
	}
	if eff.PrimaryColor != DefaultPrimaryColor {
		t.Errorf("PrimaryColor: want %q, got %q", DefaultPrimaryColor, eff.PrimaryColor)
	}
	if eff.LogoURL != "" {
		t.Errorf("LogoURL: want empty, got %q", eff.LogoURL)
	}
}

func TestEffectivePreservesNonEmpty(t *testing.T) {
	cfg := Config{ProductName: "Acme Mail", PrimaryColor: "#ff0000", LogoURL: "https://acme.test/logo.png"}
	eff := cfg.Effective()
	if eff.ProductName != "Acme Mail" || eff.PrimaryColor != "#ff0000" || eff.LogoURL != "https://acme.test/logo.png" {
		t.Errorf("Effective() altered non-empty fields: %+v", eff)
	}
}
