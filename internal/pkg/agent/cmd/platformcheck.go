// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package cmd

import (
	"fmt"
	"math/bits"
	"strings"

	"github.com/shirou/gopsutil/v3/host"
)

// CheckNativePlatformCompat checks if the binary is running
// on an appropriate system. 32-bit binaries can only run on
// 32-bit systems and 64-bit binaries only run on 64-bit systems.
func CheckNativePlatformCompat() error {
	const compiledArchBits = bits.UintSize // 32 if the binary was compiled for 32 bit architecture.

	if compiledArchBits > 32 {
		// We assume that 64bit binaries can only be run on 64bit systems
		return nil
	}

	arch, err := host.KernelArch()
	if err != nil {
		return err
	}

	if strings.Contains(arch, "64") {
		return fmt.Errorf("trying to run %vBit binary on 64Bit system", compiledArchBits)
	}

	return nil
}
