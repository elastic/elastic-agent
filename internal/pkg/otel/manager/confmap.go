// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"fmt"

	"go.opentelemetry.io/collector/confmap"
)

// serviceExtensionsList returns a copy of the service::extensions list from
// config, or nil if the key is not set. It returns an error if the value is
// set but is not a []interface{}.
func serviceExtensionsList(config *confmap.Conf) ([]interface{}, error) {
	if !config.IsSet("service::extensions") {
		return nil, nil
	}
	raw := config.Get("service::extensions")
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("service::extensions: expected []interface{}, got %T", raw)
	}
	result := make([]interface{}, len(list))
	copy(result, list)
	return result, nil
}

// mergeWithExtensions merges src into dst using confmap.Conf.Merge semantics
// for all keys, except for service::extensions where the two lists are unioned:
// dst's original entries come first, then any src-only entries are appended.
// This prevents confmap's list-overwrite semantics from silently dropping
// extensions already registered in dst.
func mergeWithExtensions(dst, src *confmap.Conf) error {
	dstExtensions, err := serviceExtensionsList(dst)
	if err != nil {
		return fmt.Errorf("merge into service::extensions failed: %w", err)
	}
	srcExtensions, err := serviceExtensionsList(src)
	if err != nil {
		return fmt.Errorf("merge into service::extensions failed: %w", err)
	}

	if err := dst.Merge(src); err != nil {
		return err
	}

	// If at most one side contributes extensions, the merge result is correct:
	// either nothing was present (both nil/empty) or one side provided the full list.
	if len(dstExtensions) == 0 || len(srcExtensions) == 0 {
		return nil
	}

	// After the merge, dst's service::extensions equals srcExtensions (overwritten).
	// Rebuild the union: dst's original entries first, then any src-only entries.
	inDst := make(map[interface{}]struct{}, len(dstExtensions))
	for _, e := range dstExtensions {
		inDst[e] = struct{}{}
	}
	combined := make([]interface{}, len(dstExtensions), len(dstExtensions)+len(srcExtensions))
	copy(combined, dstExtensions)
	for _, e := range srcExtensions {
		if _, ok := inDst[e]; !ok {
			combined = append(combined, e)
		}
	}
	if len(combined) == len(dstExtensions) {
		return nil // all src entries were already in dst; no write needed
	}
	return dst.Merge(confmap.NewFromStringMap(map[string]any{
		"service::extensions": combined,
	}))
}
