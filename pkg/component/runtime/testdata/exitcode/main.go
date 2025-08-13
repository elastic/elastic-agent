package main

import (
	"os"
	"strconv"
)

var ExitCode = "0" // string so it can be set at build time

func main() {
	exitCode, err := strconv.Atoi(ExitCode)
	if err != nil {
		exitCode = -1
	}
	os.Exit(exitCode)
}
