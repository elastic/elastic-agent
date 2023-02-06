package features

import (
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

var (
	flags flagsCfg
	mu    sync.Mutex
)

type flagsCfg struct {
	FQDN *config.Config `json:"fqdn" yaml:"fqdn" config:"fqdn"`
}

type cfg struct {
	Agent struct {
		Features flagsCfg `json:"features" yaml:"features" config:"features"`
	} `json:"agent" yaml:"agent" config:"agent"`
}

func Parse(c *config.Config) error {
	if c == nil {
		return nil
	}

	parsedFlags := cfg{}
	if err := c.Unpack(&parsedFlags); err != nil {
		return fmt.Errorf("could not umpack features config: %w", err)
	}

	mu.Lock()
	defer mu.Unlock()
	flags = parsedFlags.Agent.Features

	return nil
}

// FQDN reports if FQDN should be used instead of hostname for host.name.
func FQDN() bool {
	return flags.FQDN.Enabled()
}
