package features

import (
	"fmt"
	"sync"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

var (
	// flags flagsCfg
	mu sync.Mutex

	flags fflags
)

type fflags struct {
	fqdn bool
}

func Parse(c *config.Config) error {
	type cfg struct {
		Agent struct {
			Features struct {
				FQDN *config.Config `json:"fqdn" yaml:"fqdn" config:"fqdn"`
			} `json:"features" yaml:"features" config:"features"`
		} `json:"agent" yaml:"agent" config:"agent"`
	}

	if c == nil {
		logp.L().Infof("feature flags nil config, nothing to do: fqdn")

		return nil
	}

	parsedFlags := cfg{}
	if err := c.Unpack(&parsedFlags); err != nil {
		return fmt.Errorf("could not umpack features config: %w", err)
	}

	logp.L().Infof("feature flags parsed: fqdn: %t",
		parsedFlags.Agent.Features.FQDN.Enabled())

	mu.Lock()
	defer mu.Unlock()
	flags = fflags{fqdn: parsedFlags.Agent.Features.FQDN.Enabled()}

	return nil
}

// FQDN reports if FQDN should be used instead of hostname for host.name.
func FQDN() bool {
	mu.Lock()
	defer mu.Unlock()
	return flags.fqdn
}

func ProtoFeatures() proto.Features {
	mu.Lock()
	defer mu.Unlock()
	return proto.Features{
		Fqdn: &proto.FQDNFeature{
			Enabled: flags.fqdn}}
}
