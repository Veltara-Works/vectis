package orchestrator

import (
	"slices"
	"testing"
)

func TestNonDataStopOrder_ExcludesDataServices(t *testing.T) {
	order := NonDataStopOrder()
	for _, svc := range order {
		if DataServices[svc] {
			t.Errorf("non-data stop order contains data service %q; postgres+valkey must stay up so psql restore can connect", svc)
		}
	}

	full := ServiceStopOrder()
	if len(order) != len(full)-len(DataServices) {
		t.Errorf("non-data stop order has wrong length: got %d, want %d (full=%d, data=%d)",
			len(order), len(full)-len(DataServices), len(full), len(DataServices))
	}

	if !slices.Contains(order, "api") {
		t.Errorf("non-data stop order must contain api")
	}
}

func TestNonDataStartOrder_ExcludesDataServices(t *testing.T) {
	order := NonDataStartOrder()
	for _, svc := range order {
		if DataServices[svc] {
			t.Errorf("non-data start order contains data service %q; they were never stopped, so shouldn't be restarted", svc)
		}
	}

	// Order must match ServiceStartOrder with data services filtered out.
	want := make([]string, 0, len(ServiceStartOrder))
	for _, s := range ServiceStartOrder {
		if !DataServices[s] {
			want = append(want, s)
		}
	}
	if !slices.Equal(order, want) {
		t.Errorf("non-data start order = %v, want %v", order, want)
	}
}

// Deprecated-alias smoke tests — ensure the old names still resolve to the new.
func TestRollbackAliases_MatchNonDataOrders(t *testing.T) {
	if !slices.Equal(RollbackStopOrder(), NonDataStopOrder()) {
		t.Error("RollbackStopOrder must alias NonDataStopOrder")
	}
	if !slices.Equal(RollbackStartOrder(), NonDataStartOrder()) {
		t.Error("RollbackStartOrder must alias NonDataStartOrder")
	}
}
