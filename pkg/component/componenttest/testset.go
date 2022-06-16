package componenttest

import (
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent/pkg/component"
)

func LoadComponents() (component.ComponentSet, error) {
	_, testFile, _, _ := runtime.Caller(0)
	level := 3
	rootDir := testFile
	for i := 0; i <= level; i++ {
		rootDir = filepath.Dir(rootDir)
	}

	return component.LoadComponents(filepath.Join(rootDir, "specs"))
}
