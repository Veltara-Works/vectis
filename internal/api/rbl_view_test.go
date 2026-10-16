package api

import (
	"testing"

	"github.com/Veltara-Works/vectis/internal/mail"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// Copilot finding 1: lists with no stored result (a run in progress, or a
// failed write) are shown as unknown, so one clean row can't read as all-clear.
func TestViewRBLChecksFillsMissingListsAsUnknown(t *testing.T) {
	views, listed, unknown := viewRBLChecks([]repository.RBLCheck{
		{RBLName: "zen.spamhaus.org", Status: repository.RBLStatusClean},
	})
	if len(views) != len(mail.DefaultBlocklists) {
		t.Fatalf("views = %d, want one per list (%d)", len(views), len(mail.DefaultBlocklists))
	}
	if listed != 0 || unknown != len(mail.DefaultBlocklists)-1 {
		t.Errorf("listed=%d unknown=%d, want 0 and %d", listed, unknown, len(mail.DefaultBlocklists)-1)
	}
	for _, v := range views {
		if v.ListName == "" {
			t.Errorf("%s: missing list name", v.RBLName)
		}
		if v.RBLName != "zen.spamhaus.org" && (v.Status != repository.RBLStatusUnknown || v.Response == nil || *v.Response != "not checked yet") {
			t.Errorf("%s: %q %v, want unknown / not checked yet", v.RBLName, v.Status, v.Response)
		}
	}
}

func TestViewRBLChecksNoRowsIsAnEmptyListNotNull(t *testing.T) {
	views, _, unknown := viewRBLChecks(nil)
	if views == nil || unknown != len(mail.DefaultBlocklists) {
		t.Errorf("views=%v unknown=%d, want every list unknown", views, unknown)
	}
}
