//go:build windows

package cmd

// no-op for windows for now
func isEnrollable() (bool, error) {
	return true, nil
}
