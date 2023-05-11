package coordinator

import (
	"flag"
	"os"
	"testing"

	"github.com/elastic/elastic-agent/pkg/component/fake/bintools"
)

func TestMain(m *testing.M) {
	flag.Parse()

	os.Exit(bintools.TestMain(m))
}
