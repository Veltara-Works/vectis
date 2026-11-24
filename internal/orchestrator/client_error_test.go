package orchestrator

import "testing"

func TestOrchestratorErrorMessage(t *testing.T) {
	cases := map[string]string{
		`{"error":{"code":"RELEASE_CHANNEL_UNAVAILABLE","message":"release channel unavailable: timeout"}}`: "release channel unavailable: timeout",
		`{"error":"plan expired"}`:       "plan expired",
		`{"error":{"code":"ONLY_CODE"}}`: "ONLY_CODE",
		`not json`:                       "",
		`{"other":1}`:                    "",
	}
	for body, want := range cases {
		if got := orchestratorErrorMessage([]byte(body)); got != want {
			t.Errorf("orchestratorErrorMessage(%s) = %q, want %q", body, got, want)
		}
	}
}
