package engine

import (
	"fmt"
	"reflect"
	"sort"

	"gopkg.in/yaml.v3"
)

// ComposeServiceChanges compares two docker-compose files service by service
// (#262): Changed have a different definition (environment, healthcheck,
// mem_limit, mounts, image, …), Added are new, Removed are gone. Each list is
// sorted. Formatting, comments and key order don't count; only the decoded
// values do. An empty old compose (fresh install) reports every service as
// added.
func ComposeServiceChanges(oldCompose, newCompose []byte) (changed, added, removed []string, err error) {
	oldSvcs, err := composeServiceMap(oldCompose)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse live compose: %w", err)
	}
	newSvcs, err := composeServiceMap(newCompose)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse rendered compose: %w", err)
	}
	for name, def := range newSvcs {
		prev, ok := oldSvcs[name]
		switch {
		case !ok:
			added = append(added, name)
		case !reflect.DeepEqual(prev, def):
			changed = append(changed, name)
		}
	}
	for name := range oldSvcs {
		if _, ok := newSvcs[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(changed)
	sort.Strings(added)
	sort.Strings(removed)
	return changed, added, removed, nil
}

func composeServiceMap(compose []byte) (map[string]any, error) {
	var doc struct {
		Services map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, err
	}
	if doc.Services == nil {
		return map[string]any{}, nil
	}
	return doc.Services, nil
}
