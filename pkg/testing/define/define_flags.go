package define

import (
	"flag"
	"strings"
)

var (
	DryRun    bool
	Groups    []string
	Platforms []string

	groupStringFlag    *string
	platformStringFlag *string
)

func RegisterFlags(prefix string, set *flag.FlagSet) {
	set.BoolVar(&DryRun, prefix+"dry-run", false, "Forces test in dry-run mode: drops platform/group/sudo requirements")
	groupStringFlag = set.String(prefix+"groups", "", "test groups, comma-separated")
	platformStringFlag = set.String(prefix+"plarforms", "", "test platforms, comma-separated")
}

func ParseFlags() {
	Groups = splitStringToArray(groupStringFlag)
	Platforms = splitStringToArray(platformStringFlag)
}

func splitStringToArray(stringFlag *string) []string {
	if stringFlag == nil {
		return nil
	}
	return strings.Split(*stringFlag, ",")
}
