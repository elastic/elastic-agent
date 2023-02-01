package features

import (
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

var (
	featureFlags configs
	mu           sync.Mutex
)

type configs struct {
	FQDN struct {
		Enabled bool `json:"enabled" yaml:"enabled" config:"enabled"`
	} `json:"fqdn" yaml:"fqdn" config:"fqdn"`
}

func Parse(c config.Config) error {
	feats := configs{}
	if err := c.Unpack(&feats); err != nil {
		return fmt.Errorf("could not umpack features config: %w", err)
	}

	mu.Lock()
	defer mu.Unlock()
	featureFlags = feats

	return nil
}

// FQDN reports if FQDN should be used instead of hostname for host.name.
func FQDN() bool {
	return featureFlags.FQDN.Enabled
}
