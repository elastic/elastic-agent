// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package download

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

const packagePermissions = 0o660

type fileOps struct {
	// The following are abstractions for stdlib functions so that we can mock them in tests.
	copy             func(dst io.Writer, src io.Reader) (int64, error)
	mkdirAll         func(name string, perm os.FileMode) error
	openFile         func(name string, flag int, perm os.FileMode) (*os.File, error)
	isDiskSpaceError func(err error) bool
}

func defaultFileOps() fileOps {
	return fileOps{
		copy:             io.Copy,
		mkdirAll:         os.MkdirAll,
		openFile:         os.OpenFile,
		isDiskSpaceError: IsDiskSpaceError,
	}
}

type downloadFunc func(context.Context, *logger.Logger, *Config, *details.Details, string, string) error

func doWithRetries(ctx context.Context, log *logger.Logger, config *Config, upgradeDetails *details.Details, source string, dst string, downloadFn downloadFunc) error {
	if downloadFn == nil {
		return fmt.Errorf("download function cannot be nil")
	}

	cancelDeadline := time.Now().Add(config.Timeout)
	cancelCtx, cancel := context.WithDeadline(ctx, cancelDeadline)
	defer cancel()

	upgradeDetails.SetRetryUntil(&cancelDeadline)

	expBo := backoff.NewExponentialBackOff()
	expBo.InitialInterval = config.RetrySleepInitDuration
	boCtx := backoff.WithContext(expBo, cancelCtx)

	var attempt uint
	opFn := func() error {
		attempt++
		log.Infof("download attempt %d", attempt)
		if err := downloadFn(cancelCtx, log, config, upgradeDetails, source, dst); err != nil {
			if IsDiskSpaceError(err) {
				log.Infof("insufficient disk space error detected, stopping retries")
				return backoff.Permanent(err)
			}
			return err
		}
		return nil
	}

	opFailureNotificationFn := func(err error, retryAfter time.Duration) {
		log.Warnf("download attempt %d failed: %s; retrying in %s.",
			attempt, err.Error(), retryAfter)
		upgradeDetails.SetRetryableError(err)
	}

	if err := backoff.RetryNotify(opFn, boCtx, opFailureNotificationFn); err != nil {
		return err
	}

	upgradeDetails.SetRetryableError(nil)
	upgradeDetails.SetRetryUntil(nil)
	return nil
}

func download(ctx context.Context, log *logger.Logger, config *Config, upgradeDetails *details.Details, client *http.Client, sourceURI string, destinationPath string, ops fileOps) (err error) {
	defer func() {
		if err != nil {
			if removeErr := os.Remove(destinationPath); removeErr != nil && !os.IsNotExist(removeErr) {
				log.Warnf("failed to cleanup %s: %v", destinationPath, removeErr)
			}
		}
	}()

	if client == nil {
		client, err = config.Client(
			httpcommon.WithAPMHTTPInstrumentation(),
			httpcommon.WithKeepaliveSettings{Disable: false, IdleConnTimeout: 30 * time.Second},
			httpcommon.WithModRoundtripper(func(rt http.RoundTripper) http.RoundTripper {
				return WithHeaders(rt, Headers)
			}),
		)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequest("GET", sourceURI, nil)
	if err != nil {
		return errors.New(err, fmt.Sprintf("building request %s failed", sourceURI), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}

	if destinationDir := filepath.Dir(destinationPath); destinationDir != "" && destinationDir != "." {
		if err := ops.mkdirAll(destinationDir, 0o755); err != nil {
			return errors.New(err, fmt.Sprintf("creating directory %s failed", destinationPath), errors.TypeFilesystem, errors.M(errors.MetaKeyURI, destinationPath))
		}
	}

	destinationFile, err := ops.openFile(destinationPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, packagePermissions)
	if err != nil {
		return goerrors.Join(errors.New(fmt.Sprintf("creating %s failed", destinationPath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, destinationPath)), err)
	}
	defer destinationFile.Close()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return errors.New(err, fmt.Sprintf("fetching %s failed", sourceURI), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("fetching %q returned unsuccessful status code: %d", sourceURI, resp.StatusCode), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}

	fileSize := -1
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if length, err := strconv.Atoi(contentLength); err == nil {
			fileSize = length
		}
	}

	observers := []progressObserver{newLoggingProgressObserver(log, config.Timeout)}
	if upgradeDetails != nil {
		observers = append(observers, newDetailsProgressObserver(upgradeDetails))
	}
	dp := newDownloadProgressReporter(sourceURI, config.Timeout, fileSize, observers...)
	dp.Report(ctx)

	_, err = ops.copy(destinationFile, io.TeeReader(resp.Body, dp))
	if err != nil {
		reportedErr := err
		if ops.isDiskSpaceError(err) {
			reportedErr = ErrInsufficientDiskSpace
		}
		dp.ReportFailed(reportedErr)
		return goerrors.Join(errors.New(fmt.Sprintf("writing file %s failed", sourceURI), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI)), err)
	}
	dp.ReportComplete()

	return nil
}

func copy(log *logger.Logger, sourcePath string, targetPath string, ops fileOps) (err error) {
	defer func() {
		if err != nil {
			if removeErr := os.Remove(targetPath); removeErr != nil && !os.IsNotExist(removeErr) {
				log.Warnf("failed to cleanup %s: %v", targetPath, removeErr)
			}
		}
	}()

	sourcePath = strings.TrimPrefix(sourcePath, "file://")
	sourceFile, err := ops.openFile(sourcePath, os.O_RDONLY, packagePermissions)
	if err != nil {
		return errors.New(err, fmt.Sprintf("opening %s file failed", sourcePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, targetPath))
	}
	defer sourceFile.Close()

	if destinationDir := filepath.Dir(targetPath); destinationDir != "" && destinationDir != "." {
		if err := ops.mkdirAll(destinationDir, 0o755); err != nil {
			return err
		}
	}

	destinationFile, err := ops.openFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, packagePermissions)
	if err != nil {
		return errors.New(err, fmt.Sprintf("opening %s file failed", sourcePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, targetPath))
	}
	defer destinationFile.Close()

	if _, err = ops.copy(destinationFile, sourceFile); err != nil {
		return err
	}

	return nil
}

func Fetch(ctx context.Context, log *logger.Logger, config *Config, upgradeDetails *details.Details, source, targetPath string) (err error) {
	if IsLocal(source) {
		err = copy(log, source, targetPath, defaultFileOps())
	} else {
		err = doWithRetries(ctx, log, config, upgradeDetails, source, targetPath,
			func(ctx context.Context, log *logger.Logger, config *Config, upgradeDetails *details.Details, source, dst string) error {
				return download(ctx, log, config, upgradeDetails, nil, source, dst, defaultFileOps())
			})
	}

	if err != nil {
		return fmt.Errorf("could not fetch %s to %s: %w", source, targetPath, err)
	}

	return nil
}
