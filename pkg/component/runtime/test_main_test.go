package runtime

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/elastic/elastic-agent/pkg/component/fake/bintools"
)

func TestMain(m *testing.M) {
	flag.Parse()

	bintools.CompileBinary(bintools.PathBinComponent, bintools.PathPkgComponent)
	bintools.CompileBinary(bintools.PathBinShipper, bintools.PathPkgShipper)

	exitCode := m.Run()

	err := bintools.RemoveBinaries(bintools.PathBinComponent, bintools.PathBinShipper)

	switch {
	case exitCode == 0 && err != nil:
		fmt.Printf("test clean up failed: %v\n", err)
	case exitCode != 0 && err == nil:
		fmt.Printf("test exited with code %d but clean up succeeded: %v\n",
			exitCode, err)
	case exitCode != 0 && err != nil:
		fmt.Printf("test exited with code %d and clean up failed: %v\n",
			exitCode, err)
	}

	os.Exit(exitCode)
}
