// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package operation

import (
	"context"
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/core/state"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// operationFetch fetches artifact from preconfigured source
// skips if artifact is already downloaded
type operationFetch struct {
	logger         *logger.Logger
	program        Descriptor
	operatorConfig *configuration.SettingsConfig
	downloader     download.Downloader
}

func newOperationFetch(
	logger *logger.Logger,
	program Descriptor,
	operatorConfig *configuration.SettingsConfig,
	downloader download.Downloader) *operationFetch {

	return &operationFetch{
		logger:         logger,
		program:        program,
		operatorConfig: operatorConfig,
		downloader:     downloader,
	}
}

// Name is human readable name identifying an operation
func (o *operationFetch) Name() string {
	return "operation-fetch"
}

var downloaded map[string]int = map[string]int{}

// Check checks whether fetch needs to occur.
//
// If the artifacts already exists then fetch will not be ran.
func (o *operationFetch) Check(_ context.Context, _ Application) (bool, error) {
	downloadConfig := o.operatorConfig.DownloadConfig
	fullPath, err := artifact.GetArtifactPath(o.program.Spec(), o.program.Version(), downloadConfig.OS(), downloadConfig.Arch(), downloadConfig.TargetDirectory)
	if err != nil {
		return false, err
	}

	if release.DevInsecure() {
		fmt.Println(o.program.Spec().Cmd, "**************************************************************************************************", downloaded)
		// does this need to be goroutine safe?
		if count := downloaded[fullPath]; count < 2 {
			o.logger.Info("====================================================== running in dev mode, forcing downloading Beats once")
			downloaded[fullPath] = count + 1
			return true, nil
		}
	}

	_, err = os.Stat(fullPath)
	if os.IsNotExist(err) {
		return true, nil
	}

	o.logger.Debugf("binary '%s.%s' already exists in %s. Skipping operation %s", o.program.BinaryName(), o.program.Version(), fullPath, o.Name())
	return false, err
}

// Run runs the operation
func (o *operationFetch) Run(ctx context.Context, application Application) (err error) {
	defer func() {
		if err != nil {
			application.SetState(state.Failed, err.Error(), nil)
		}
	}()

	fullPath, err := o.downloader.Download(ctx, o.program.Spec(), o.program.Version())
	if err == nil {
		fmt.Println("################################## Downloaded:", o.program.BinaryName(), "at: ", fullPath)
		o.logger.Infof("downloaded binary '%s.%s' into '%s' as part of operation '%s'", o.program.BinaryName(), o.program.Version(), fullPath, o.Name())
	}

	return err
}
