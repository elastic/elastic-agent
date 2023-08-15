//go:build integration

package integration

import "testing"

func TestLinter(t *testing.T) {
	callUndefinedFunction()
}
