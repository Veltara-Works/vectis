package orchestrator

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
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

// VectisImageServices must enumerate every service in the compose template
// whose image references `ghcr.io/veltara-works/vectis-<service>`. Regression
// test for rc33: pre-fix, orchestrator + cert-extractor were in compose but
// absent from the list, so Plan.Changes silently dropped them and they were
// left stranded on the old tag after Apply.
func TestVectisImageServices_MatchesComposeTemplate(t *testing.T) {
	tmplPath := filepath.Join("..", "..", "templates", "docker-compose.yml.tmpl")
	data, err := os.ReadFile(tmplPath)
	if err != nil {
		t.Fatalf("read compose template: %v", err)
	}

	// Match `image: ghcr.io/veltara-works/vectis-<name>:...` and capture <name>.
	re := regexp.MustCompile(`image:\s*ghcr\.io/veltara-works/vectis-([a-z0-9-]+):`)
	matches := re.FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		t.Fatal("compose template contained no vectis-* image lines — template path wrong or template changed drastically")
	}

	declared := make(map[string]bool, len(matches))
	for _, m := range matches {
		declared[m[1]] = true
	}

	listed := make(map[string]bool, len(VectisImageServices))
	for _, s := range VectisImageServices {
		listed[s] = true
	}

	var missingFromList []string
	for svc := range declared {
		if !listed[svc] {
			missingFromList = append(missingFromList, svc)
		}
	}
	var strandedInList []string
	for svc := range listed {
		if !declared[svc] {
			strandedInList = append(strandedInList, svc)
		}
	}
	sort.Strings(missingFromList)
	sort.Strings(strandedInList)

	if len(missingFromList) > 0 {
		t.Errorf("VectisImageServices missing compose-declared services: %v — add to config.go or Plan will silently skip them", missingFromList)
	}
	if len(strandedInList) > 0 {
		t.Errorf("VectisImageServices lists services absent from compose template: %v — remove from config.go", strandedInList)
	}
}
