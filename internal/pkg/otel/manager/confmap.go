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
// set but is not a []any.
func serviceExtensionsList(config *confmap.Conf) ([]any, error) {
	if !config.IsSet("service::extensions") {
		return nil, nil
	}
	raw := config.Get("service::extensions")
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("service::extensions: expected []any, got %T", raw)
	}
	result := make([]any, len(list))
	copy(result, list)
	return result, nil
}

// mergeWithExtensions merges src into dst using confmap.Conf.Merge semantics
// for all keys, except for service::extensions where the two lists are unioned
// with ordering consistent with both input lists. Elements common to both
// lists act as anchors: unique elements that precede an anchor in their
// respective list are interleaved before it, preserving each list's relative
// ordering in the result.
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
	// either nothing was present or one side provided the full list.
	if len(dstExtensions) == 0 || len(srcExtensions) == 0 {
		return nil
	}

	// After the merge, dst's service::extensions equals srcExtensions (overwritten).
	// Rebuild the union with ordering consistent with both input lists.
	combined := mergeExtensionLists(dstExtensions, srcExtensions)
	return dst.Merge(confmap.NewFromStringMap(map[string]any{
		"service::extensions": combined,
	}))
}

// mergeExtensionLists returns the union of dst and src preserving the ordering
// within each list. Shared elements (present in both lists) act as
// synchronisation points: all dst-only elements up to a shared element are
// emitted first, then all src-only elements preceding it in src, then the
// shared element itself. Remaining src-only elements are appended at the end.
func mergeExtensionLists(dst, src []any) []any {
	inSrc := make(map[any]struct{}, len(src))
	for _, e := range src {
		inSrc[e] = struct{}{}
	}
	inDst := make(map[any]struct{}, len(dst))
	for _, e := range dst {
		inDst[e] = struct{}{}
	}

	result := make([]any, 0, len(dst)+len(src))
	j := 0 // current position in src

	for _, e := range dst {
		if _, shared := inSrc[e]; shared {
			// Advance src to this shared element, collecting src-only elements.
			for j < len(src) && src[j] != e {
				if _, ok := inDst[src[j]]; !ok {
					result = append(result, src[j])
				}
				j++
			}
			result = append(result, e)
			j++ // step past the shared element in src
		} else {
			result = append(result, e)
		}
	}

	// Append any remaining src-only elements.
	for ; j < len(src); j++ {
		if _, ok := inDst[src[j]]; !ok {
			result = append(result, src[j])
		}
	}

	return result
}
