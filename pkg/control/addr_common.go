package control

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
)

// AddressFromPath returns the connection address for an Elastic Agent running on the defined platform, and it's
// executing directory.
func AddressFromPath(platform string, path string) string {
	dataPath := filepath.Join(path, "data")
	if platform == "windows" {
		return fmt.Sprintf(`\\.\pipe\elastic-agent-%x`, sha256.Sum256([]byte(dataPath)))
	}
	socketPath := filepath.Join(dataPath, "tmp", "elastic-agent-control")
	socketPath = fmt.Sprintf("unix://%s.sock", socketPath)
	// unix socket path must be less than 104 characters
	if len(socketPath) < 104 {
		return socketPath
	}
	// place in global /tmp to ensure that its small enough to fit; current path is way to long
	// for it to be used, but needs to be unique per Agent (in the case that multiple are running)
	return fmt.Sprintf(`unix:///tmp/elastic-agent/%x.sock`, sha256.Sum256([]byte(socketPath)))
}
