package bintools

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/pkg/component"
)

const ExtExe = ".exe"

var (
	PathBinShipper   = BinaryPath("shipper")
	PathBinComponent = BinaryPath("component")

	PathPkgShipper, _   = path.Split("shipper")
	PathPkgComponent, _ = path.Split("component")
)

func RemoveBinaries(binaries ...string) error {
	const envVarRemoveBinaries = "REMOVE_FAKE_BINARIES"
	removeBinaries := os.Getenv(envVarRemoveBinaries)

	remove, err := strconv.ParseBool(removeBinaries)
	if err != nil {
		remove = true // if anything fails, keep the default
		fmt.Printf("could not parse %s: %v", envVarRemoveBinaries, err)
	}

	if !remove {
		fmt.Println("not removing binaries")
	}

	var multErr *multierror.Error
	for _, b := range binaries {
		err := os.Remove(PathBinComponent)
		if err != nil {
			multErr = multierror.Append(multErr, fmt.Errorf(
				"failed to remove %s: %q: %v", b, err))

		}

	}

	return multErr
}

func BinaryPath(name string) string {
	binaryPath := filepath.Join("..", "fake", name, name)

	if runtime.GOOS == component.Windows {
		binaryPath += ExtExe
	}

	return binaryPath
}

func CompileBinary(out string, packagePath string) {
	var outBuff bytes.Buffer
	var errBuff bytes.Buffer

	cmd := exec.Command(
		"go",
		"build",
		"-gcflags=all=-N -l",
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
