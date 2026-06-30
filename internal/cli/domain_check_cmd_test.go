package cli

import "testing"

func TestClassifySPF(t *testing.T) {
	tests := []struct {
		name string
		txts []string
		want checkStatus
	}{
		{"hard fail", []string{"v=spf1 mx a -all"}, statusPass},
		{"soft fail", []string{"v=spf1 include:_spf.example.com ~all"}, statusPass},
		{"permissive +all", []string{"v=spf1 mx +all"}, statusWarn},
		{"neutral ?all", []string{"v=spf1 mx ?all"}, statusWarn},
		{"no all qualifier", []string{"v=spf1 mx a"}, statusWarn},
		{"missing", []string{"some-other-txt", "google-site-verification=x"}, statusFail},
		{"duplicate spf", []string{"v=spf1 mx -all", "v=spf1 a -all"}, statusFail},
		{"case insensitive prefix", []string{"V=SPF1 MX -all"}, statusPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySPF(tt.txts); got.Status != tt.want {
				t.Errorf("classifySPF(%v) = %s (%q), want %s", tt.txts, got.Status, got.Detail, tt.want)
			}
		})
	}
}

func TestClassifyDMARC(t *testing.T) {
	tests := []struct {
		name string
		txts []string
		want checkStatus
	}{
		{"reject", []string{"v=DMARC1; p=reject; rua=mailto:d@x.com"}, statusPass},
		{"quarantine", []string{"v=DMARC1; p=quarantine"}, statusPass},
		{"monitor only", []string{"v=DMARC1; p=none"}, statusWarn},
		{"no policy tag", []string{"v=DMARC1; rua=mailto:d@x.com"}, statusWarn},
		{"missing", []string{"unrelated"}, statusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyDMARC(tt.txts); got.Status != tt.want {
				t.Errorf("classifyDMARC(%v) = %s (%q), want %s", tt.txts, got.Status, got.Detail, tt.want)
			}
		})
	}
}

func TestClassifyDKIM(t *testing.T) {
	const pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
	tests := []struct {
		name        string
		txts        []string
		expectedB64 string
		want        checkStatus
	}{
		{"match", []string{"v=DKIM1; k=rsa; p=" + pub}, pub, statusPass},
		{"mismatch", []string{"v=DKIM1; k=rsa; p=DIFFERENTKEY"}, pub, statusFail},
		{"published no local key", []string{"v=DKIM1; k=rsa; p=" + pub}, "", statusWarn},
		{"empty p", []string{"v=DKIM1; k=rsa; p="}, pub, statusFail},
		{"missing record", []string{"nothing here"}, pub, statusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyDKIM(tt.txts, "sel202607", tt.expectedB64); got.Status != tt.want {
				t.Errorf("classifyDKIM = %s (%q), want %s", got.Status, got.Detail, tt.want)
			}
		})
	}
}

func TestExtractDKIMPub(t *testing.T) {
	cases := map[string]string{
		"v=DKIM1; k=rsa; p=ABC123":   "ABC123",
		"p=XYZ; v=DKIM1":             "XYZ",
		"v=DKIM1; k=rsa":             "",
		"v=DKIM1; k=rsa; p= SPACED ": "SPACED",
	}
	for in, want := range cases {
		if got := extractDKIMPub(in); got != want {
			t.Errorf("extractDKIMPub(%q) = %q, want %q", in, got, want)
		}
	}
}
