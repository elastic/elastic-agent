// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package capabilities

type stringMatcher struct {
	// The pattern to match against, a string that can use '*' as a wildcard
	// by itself or in between slashes, e.g.
	// "system/metrics" matches the patterns "*", "system/*", "*/metrics".
	pattern string

	// Whether matching this pattern results in allowing or denying the
	// corresponding string.
	rule allowOrDeny
}

func matchString(str string, matchers []*stringMatcher) bool {
	for _, matcher := range matchers {
		if matchesExpr(matcher.pattern, str) {
			// The check passed, allow or reject as appropriate
			return matcher.rule == ruleTypeAllow
		}
	}
	// If nothing blocked it, default to allow.
	return true
}
