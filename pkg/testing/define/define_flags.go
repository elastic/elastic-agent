package define

import (
	"github.com/spf13/pflag"
)

var (
	DryRun    bool
	Groups    []string
	Platforms []string
)

func RegisterFlags(prefix string, set *pflag.FlagSet) {
	set.BoolVar(&DryRun, prefix+"dry-run", false, "Forces test in dry-run mode: drops platform/group/sudo requirements")
	set.StringArrayVar(&Groups, prefix+"groups", nil, "test groups")
	set.StringArrayVar(&Platforms, prefix+"plarforms", nil, "test platforms")
}
