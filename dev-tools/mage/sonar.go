// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mage

import (
	"context"
	"fmt"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"strings"
)

type GoSonarArgs struct {
	Version      string   // Test name used in logging.
	ScannerOpts  []string // Enable race detector.
	Token        string
	Organization string
	ProjectKey   string
	SonarHostUrl string
}

type SonarCloud mg.Namespace

func DefaultGoSonarArgs() GoSonarArgs {
	params := GoSonarArgs{
		Version:      SonarVersion,
		ScannerOpts:  strings.Split(SonarScannerOpt, " "),
		Token:        SonarToken,
		Organization: SonarOrg,
		ProjectKey:   SonarProjectKey,
		SonarHostUrl: SonarHostUrl,
	}

	return params
}

// UploadSonarCloud Upload testcoverage to SonarlCloud
func (SonarCloud) UploadSonarCloud() {
	//TODO validate that we have a coverage repot to upload
	//TODO validate that we have the right variables for SonarCloud
	mg.SerialDeps(GoUploadSonarCloud)
}

func GoUploadSonarCloud(ctx context.Context) error {
	params := DefaultGoSonarArgs()
	fmt.Println(">> sonarcloud:", params.SonarHostUrl)

	dockerRun := sh.RunCmd("docker", "run")
	var args []string
	sonarImage := fmt.Sprintf("sonarsource/sonar-scanner-cli:%s", params.Version)

	args = append(args, sonarImage)
	return dockerRun(args...)
}
