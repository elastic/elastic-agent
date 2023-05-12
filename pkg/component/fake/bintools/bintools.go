package bintools

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/pkg/component"
)

const ExtExe = ".exe"

var (
	PathBinShipper   = BinaryPath("shipper")
	PathBinComponent = BinaryPath("component")

	PathPkgShipper, _   = filepath.Split(PathBinShipper)
	PathPkgComponent, _ = filepath.Split(PathBinComponent)
)

// TestMain compiles the fake binaries, calls m.Run(), remove the binaries if
// KEEP_FAKE_BINARIES isn't true, prints any error and finally returns the
// exitCode returned by m.Run().
// If a package needs the fake binaries, it can define a TestMain as this:
//
//	 func TestMain(m *testing.M) {
//		flag.Parse()
//
//		os.Exit(bintools.TestMain(m))
//	 }
func TestMain(m *testing.M) int {
	CompileBinary(PathBinComponent, PathPkgComponent)
	CompileBinary(PathBinShipper, PathPkgShipper)

	exitCode := m.Run()

	err := RemoveBinaries(PathBinComponent, PathBinShipper)

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

	return exitCode
}

func RemoveBinaries(binaries ...string) error {
	const envVarRemoveBinaries = "KEEP_FAKE_BINARIES"
	keepBinaries := os.Getenv(envVarRemoveBinaries)
	if keepBinaries == "" {
		keepBinaries = "false"
	}

	keep, err := strconv.ParseBool(keepBinaries)
	if err != nil {
		fmt.Printf("could not parse %s: %v", envVarRemoveBinaries, err)
	}

	if keep {
		fmt.Printf("keeping fake binaries: %s\n", strings.Join(binaries, ", "))
		return nil
	}

	var multErr error
	for _, b := range binaries {
		err := os.Remove(b)
		if err != nil {
			multErr = multierror.Append(multErr, fmt.Errorf(
				"failed to keep %s: %v", b, err))
		}
	}

	return multErr
}

func BinaryPath(name string) string {
	_, b, _, _ := runtime.Caller(0)
	pathPkg := filepath.Dir(b)

	binaryPath := filepath.Join(pathPkg, "..", name, name)
	if runtime.GOOS == component.Windows {
		binaryPath += ExtExe
	}

	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		fmt.Printf("culd not get absolut path of %s: %v", binaryPath, err)
	}

	return absPath
}

func CompileBinary(out string, packagePath string) {
	var outBuff bytes.Buffer
	var errBuff bytes.Buffer

	cmd := exec.Command(
		"go",
		"build",
		"-gcflags=all=-N -l",
		"-buildvcs=false",
		"-o", out,
		packagePath)
	cmd.Stdout = &outBuff
	cmd.Stderr = &errBuff
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			fmt.Printf("could not compile binary: %s: %v",
				exitErr.String(),
				string(exitErr.Stderr))
			fmt.Println("the command run was:", cmd.String())

			if outBuff.Len() > 0 {
				fmt.Println("stdOut:", outBuff.String())
			}
			if errBuff.Len() > 0 {
				fmt.Println("stdErr:", errBuff.String())
			}

			os.Exit(1)
		}

		fmt.Printf("failed compiling binary: %v\n", err)
		os.Exit(1)
	}

	if runtime.GOOS != component.Windows {
		err := os.Chown(out, os.Geteuid(), os.Getgid())
		if err != nil {
			fmt.Printf("failed chown %s: %s\n", out, err)
			os.Exit(1)
		}
		err = os.Chmod(out, 0755)
		if err != nil {
			fmt.Printf("failed chmod %s: %s\n", out, err)
			os.Exit(1)
		}
	}
}
