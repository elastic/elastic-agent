package runtime

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/elastic/elastic-agent/pkg/component"
)

var (
	fakeCompBinPath    = fakeBinaryPath("component")
	fakeShipperBinPath = fakeBinaryPath("shipper")
)

func TestMain(m *testing.M) {
	flag.Parse()

	removeBinaries := os.Getenv("REMOVE_FAKE_BINARIES")

	fakeCompPackage := path.Join("..", "fake", "component")
	fakeShipperPackage := path.Join("..", "fake", "shipper")

	compileBinary(fakeCompBinPath, fakeCompPackage)
	compileBinary(fakeShipperBinPath, fakeShipperPackage)

	exitCode := m.Run()

	if strings.ToLower(removeBinaries) != "false" {
		errRmFakeComp := os.Remove(fakeCompBinPath)
		if errRmFakeComp != nil {
			fmt.Printf("failed to remove fake/component: %q: %v\n",
				fakeShipperBinPath, errRmFakeComp)
		}

		errRmFakeshipper := os.Remove(fakeShipperBinPath)
		if errRmFakeComp != nil {
			fmt.Printf("failed to remove fake/shipper: %q: %v\n",
				fakeShipperBinPath, errRmFakeshipper)
		}

		switch {
		case exitCode != 0 && errRmFakeComp == nil && errRmFakeshipper == nil:
			fmt.Printf("tests exited with code %d, but clean up succeeded\n",
				exitCode)
		case exitCode == 0 && (errRmFakeComp != nil || errRmFakeshipper != nil):
			fmt.Printf("test clean up failed: fake/component err:%v, fake/shipper err: %v\n",
				errRmFakeComp, errRmFakeshipper)
			exitCode = 1
		case exitCode != 0 && (errRmFakeComp != nil || errRmFakeshipper != nil):
			fmt.Printf("test exited with code %d. clean up failed: fake/component err:%v, fake/shipper err: %v\n",
				exitCode, errRmFakeComp, errRmFakeshipper)
		}
	}

	os.Exit(exitCode)
}

func fakeBinaryPath(name string) string {
	binaryPath := filepath.Join("..", "fake", name, name)

	if runtime.GOOS == component.Windows {
		binaryPath += exeExt
	}

	return binaryPath
}

func compileBinary(out string, packagePath string) {
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

	return
}
