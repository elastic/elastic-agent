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
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

const packagePermissions = 0o660

func IsLocal(source string) bool {
	return strings.HasPrefix(source, "file://") || strings.HasPrefix(source, "/")
}

type fileOps struct {
	copyFile func(dst io.Writer, src io.Reader) (int64, error)
	openFile func(name string, flag int, perm os.FileMode) (*os.File, error)
}

func defaultFileOps() fileOps {
	return fileOps{
		copyFile: io.Copy,
		openFile: os.OpenFile,
	}
}

type downloadFunc func(ctx context.Context, source, dst string) error

func downloadWithRetries(ctx context.Context, log *logger.Logger, config *artifact.Config, upgradeDetails *details.Details, source string, dst string, downloadFn downloadFunc) error {
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
		if err := downloadFn(cancelCtx, source, dst); err != nil {
			if upgradeErrors.IsPermanentHTTPError(err) {
				return backoff.Permanent(err)
			}
			if upgradeErrors.IsDiskSpaceError(err) {
				log.Infof("insufficient disk space error detected, stopping retries")
				return backoff.Permanent(err)
			}
			var agentErr errors.Error
			if goerrors.As(err, &agentErr) && agentErr.Type() == errors.TypeFilesystem {
				log.Infof("filesystem error detected, stopping retries")
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

func download(ctx context.Context, log *logger.Logger, config *artifact.Config, upgradeDetails *details.Details, client *http.Client, sourceURI string, targetPath string, ops fileOps) (err error) {
	defer func() {
		if err != nil {
			if removeErr := os.Remove(targetPath); removeErr != nil && !os.IsNotExist(removeErr) {
				log.Warnf("failed to cleanup %s: %v", targetPath, removeErr)
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURI, nil)
	if err != nil {
		return errors.New(err, fmt.Sprintf("building request %s failed", sourceURI), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}

	targetFile, err := ops.openFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, packagePermissions)
	if err != nil {
		return goerrors.Join(errors.New(fmt.Sprintf("creating %s failed", targetPath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, targetPath)), err)
	}
	defer targetFile.Close()

	resp, err := client.Do(req)
	if err != nil {
		return errors.New(err, fmt.Sprintf("fetching %s failed", sourceURI), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := errors.New(fmt.Sprintf("fetching %q returned unsuccessful status code: %d", sourceURI, resp.StatusCode), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusGone:
			return goerrors.Join(err, upgradeErrors.ErrPermanentHTTP)
		}
		return err
	}

	fileSize := -1
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		if length, err := strconv.Atoi(contentLength); err == nil {
			fileSize = length
		}
	}

	observers := []progressObserver{
		newLoggingProgressObserver(log, config.Timeout),
		newDetailsProgressObserver(upgradeDetails),
	}
	dp := newDownloadProgressReporter(sourceURI, config.Timeout, fileSize, observers...)
	dp.Report(ctx)

	_, err = ops.copyFile(targetFile, io.TeeReader(resp.Body, dp))
	if err != nil {
		reportedErr := err
		if upgradeErrors.IsDiskSpaceError(err) {
			reportedErr = upgradeErrors.ErrInsufficientDiskSpace
		}
		dp.ReportFailed(reportedErr)
		return goerrors.Join(errors.New(fmt.Sprintf("copying %s to %s failed", sourceURI, targetPath), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI)), err)
	}
	dp.ReportComplete()

	return nil
}

func copyFile(log *logger.Logger, sourcePath string, targetPath string, ops fileOps) (err error) {
	defer func() {
		if err != nil {
			if removeErr := os.Remove(targetPath); removeErr != nil && !os.IsNotExist(removeErr) {
				log.Warnf("failed to cleanup %s: %v", targetPath, removeErr)
			}
		}
	}()

	sourcePath = strings.TrimPrefix(sourcePath, "file://")
	sourceFile, err := ops.openFile(sourcePath, os.O_RDONLY, 0)
	if err != nil {
		return errors.New(err, fmt.Sprintf("opening %s file failed", sourcePath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, sourcePath))
	}
	defer sourceFile.Close()

	targetFile, err := ops.openFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, packagePermissions)
	if err != nil {
		return errors.New(err, fmt.Sprintf("creating %s file failed", targetPath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, targetPath))
	}
	defer targetFile.Close()

	if _, err = ops.copyFile(targetFile, sourceFile); err != nil {
		return err
	}

	return nil
}

func Fetch(ctx context.Context, log *logger.Logger, config *artifact.Config, upgradeDetails *details.Details, source, targetPath string) (err error) {
	if IsLocal(source) {
		err = copyFile(log, source, targetPath, defaultFileOps())
	} else {
		err = downloadWithRetries(ctx, log, config, upgradeDetails, source, targetPath,
			func(ctx context.Context, source, dst string) error {
				return download(ctx, log, config, upgradeDetails, nil, source, dst, defaultFileOps())
			})
	}

	if err != nil {
		return fmt.Errorf("could not fetch %s to %s: %w", source, targetPath, err)
	}

	return nil
}
