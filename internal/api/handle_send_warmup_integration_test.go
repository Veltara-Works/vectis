//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// A send refused for the IP warmup limit is refused before the abuse rate
// counters are charged (#287, Copilot #288 review 3), on both /send and
// /send/batch, and /send says when to retry.
func TestSendWarmupRefusalDoesNotChargeAbuseCounters(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	domains := repository.NewDomainRepo(env.pool)
	d, err := domains.Create(ctx, repository.DomainCreate{Name: fmt.Sprintf("warmup-%d.test", time.Now().UnixNano())})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	t.Cleanup(func() { domains.Delete(context.Background(), d.ID) })

	warmups := repository.NewIPWarmupRepo(env.pool)
	w, active, err := warmups.CreateIfNoneActive(ctx, "198.51.100.77", "integration")
	if err != nil || w == nil {
		t.Fatalf("start warmup = %v, active %v, %v", w, active, err)
	}
	t.Cleanup(func() { warmups.Delete(context.Background(), w.ID) })
	if _, err := env.pool.Exec(ctx, `UPDATE ip_warmup SET daily_sent = daily_limit WHERE id = $1`, w.ID); err != nil {
		t.Fatalf("use up today's limit: %v", err)
	}

	msg := fmt.Sprintf(`{"from":{"email":"noreply@%s"},"to":[{"email":"someone@example.org"}],"subject":"s","text_body":"b"}`, d.Name)

	resp := env.doRequest(t, "POST", "/api/v1/send", msg)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("/send status = %d (%s), want 429", resp.StatusCode, body)
	}
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err != nil || e.Error.Code != "WARMUP_LIMIT" {
		t.Errorf("/send error = %s, want code WARMUP_LIMIT", body)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("/send 429 has no Retry-After header")
	}

	resp = env.doRequest(t, "POST", "/api/v1/send/batch", fmt.Sprintf(`{"messages":[%s,%s]}`, msg, msg))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	var b struct {
		Data struct {
			Failed  int `json:"failed"`
			Results []struct {
				Code string `json:"code"`
			} `json:"results"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &b); err != nil || b.Data.Failed != 2 || len(b.Data.Results) != 2 ||
		b.Data.Results[0].Code != "WARMUP_LIMIT" || b.Data.Results[1].Code != "WARMUP_LIMIT" {
		t.Errorf("/send/batch = %s, want both messages refused with WARMUP_LIMIT", body)
	}

	key := fmt.Sprintf("abuse:domain:%s:%s", d.ID, time.Now().UTC().Format("2006010215"))
	if n, err := env.vk.Do(ctx, env.vk.B().Get().Key(key).Build()).AsInt64(); err == nil && n != 0 {
		t.Errorf("domain abuse counter = %d after warmup refusals, want 0 (not charged)", n)
	}
}
