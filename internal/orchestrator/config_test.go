package orchestrator

import (
	"slices"
	"testing"
)

func TestRollbackStopOrder_ExcludesDataServices(t *testing.T) {
	order := RollbackStopOrder()
	for _, svc := range order {
		if DataServices[svc] {
			t.Errorf("rollback stop order contains data service %q; postgres+valkey must stay up so psql restore can connect", svc)
		}
	}

	full := ServiceStopOrder()
	if len(order) != len(full)-len(DataServices) {
		t.Errorf("rollback stop order has wrong length: got %d, want %d (full=%d, data=%d)",
			len(order), len(full)-len(DataServices), len(full), len(DataServices))
	}

	if slices.Contains(order, "api") != true {
		t.Errorf("rollback stop order must contain api")
	}
}

func TestRollbackStartOrder_ExcludesDataServices(t *testing.T) {
	order := RollbackStartOrder()
	for _, svc := range order {
		if DataServices[svc] {
			t.Errorf("rollback start order contains data service %q; they were never stopped, so shouldn't be restarted", svc)
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
		t.Errorf("rollback start order = %v, want %v", order, want)
	}
}
