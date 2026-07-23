// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

const (
	checksumSize        = uint64(1024)                   // 1KB
	extraDataSize       = uint64(50 * 1024 * 1024)       // 50MB
	fallbackArchiveSize = uint64(700 * 1024 * 1024)      // 700MB
	fallbackPayloadSize = uint64(2 * 1024 * 1024 * 1024) // 2GB
)

type readRangeFunc func(uri string, offset, length int64) ([]byte, error)

// CheckDiskSpaceAvailable returns whether the filesystems holding
// config.TargetDirectory and paths.Data have enough free space for an upgrade.
// Returns:
//
//	true, nil: available and exact required space were determined and is sufficient
//	true, err: exact required space couldn't be determined but available space is enough for fallback estimate
//	false, err:
//	   - Space is insufficient
//	   - Available space couldn't be determined
//	   - Filesystem identity could not be determined
func CheckDiskSpaceAvailable(ctx context.Context, config *artifact.Config, upgradeDetails *details.Details, uri string) (bool, error) {
	archiveFS, err := getVolumeNameAt(config.TargetDirectory)
	if err != nil {
		return false, fmt.Errorf("could not determine volume at %s: %w", config.TargetDirectory, err)
	}
	dataFS, err := getVolumeNameAt(paths.Data())
	if err != nil {
		return false, fmt.Errorf("could not determine volume at %s: %w", paths.Data(), err)
	}

	if archiveFS == dataFS {
		available, err := getAvailableDiskSpaceAt(config.TargetDirectory)
		if err != nil {
			return false, fmt.Errorf("could not get available disk space at %s: %w", config.TargetDirectory, err)
		}
		archiveSize, decompressedSize, sizeErr := getUpgradeSize(ctx, config, uri, upgradeDetails)
		if sizeErr != nil {
			sizeErr = fmt.Errorf("could not get upgrade size: %w", sizeErr)
		}
		if available < archiveSize+checksumSize+decompressedSize+extraDataSize {
			return false, goerrors.Join(sizeErr,
				fmt.Errorf("insufficient space at %s (%q): need %d, have %d: %w", config.TargetDirectory, archiveFS, archiveSize+decompressedSize+extraDataSize, available, upgradeErrors.ErrInsufficientDiskSpace))
		}
		return true, sizeErr
	}

	archiveFSAvailable, err := getAvailableDiskSpaceAt(config.TargetDirectory)
	if err != nil {
		return false, fmt.Errorf("could not get available disk space at %s: %w", config.TargetDirectory, err)
	}
	dataFSAvailable, err := getAvailableDiskSpaceAt(paths.Data())
	if err != nil {
		return false, fmt.Errorf("could not get available disk space at %s: %w", paths.Data(), err)
	}

	archiveSize, decompressedSize, err := getUpgradeSize(ctx, config, uri, upgradeDetails)
	if err != nil {
		err = fmt.Errorf("could not get upgrade size: %w", err)
	}
	hasSpace := true
	if archiveFSAvailable < archiveSize+checksumSize {
		err = goerrors.Join(err, fmt.Errorf("insufficient space at %s (%q): need %d, have %d: %w", config.TargetDirectory, archiveFS, archiveSize, archiveFSAvailable, upgradeErrors.ErrInsufficientDiskSpace))
		hasSpace = false
	}
	if dataFSAvailable < decompressedSize+extraDataSize {
		err = goerrors.Join(err, fmt.Errorf("insufficient space at %s (%q): need %d, have %d: %w", paths.Data(), dataFS, decompressedSize+extraDataSize, dataFSAvailable, upgradeErrors.ErrInsufficientDiskSpace))
		hasSpace = false
	}

	return hasSpace, err
}

func getUpgradeSize(ctx context.Context, config *artifact.Config, uri string, upgradeDetails *details.Details) (uint64, uint64, error) {
	var archiveSize, decompressedSize uint64
	var err error
	if download.IsLocal(uri) {
		archiveSize, decompressedSize, err = GetLocalUpgradeSize(uri)
	} else {
		archiveSize, decompressedSize, err = GetRemoteUpgradeSize(ctx, config, uri, upgradeDetails)
	}

	if err != nil {
		return archiveSize, decompressedSize, goerrors.Join(upgradeErrors.ErrFetchUpgradeSizeFailed, err)
	}
	return archiveSize, decompressedSize, nil
}

func GetLocalUpgradeSize(uri string) (uint64, uint64, error) {
	decompressedSize := fallbackPayloadSize
	archiveSize := fallbackArchiveSize

	path := strings.TrimPrefix(uri, "file://")
	if info, err := os.Stat(path); err == nil {
		archiveSize = uint64(info.Size()) //nolint:gosec // G115: os.FileInfo.Size is expected to be non-negative
	} else {
		return archiveSize, decompressedSize, fmt.Errorf("could not stat %s: %w", path, err)
	}

	readRange := func(uri string, offset, length int64) ([]byte, error) {
		data := make([]byte, length)
		path := strings.TrimPrefix(uri, "file://")
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("could not open %s: %w", path, err)
		}
		defer f.Close()

		if _, err := f.ReadAt(data, offset); err != nil {
			return nil, fmt.Errorf("could not read %s: %w", path, err)
		}
		return data, nil
	}

	if strings.HasSuffix(uri, ".tar.gz") {
		if n, err := getGzipPayloadSize(uri, archiveSize, readRange); err == nil {
			decompressedSize = n
		} else {
			return archiveSize, decompressedSize, err
		}
	} else if strings.HasSuffix(uri, ".zip") {
		if n, err := getZipPayloadSize(uri, archiveSize, readRange); err == nil {
			decompressedSize = n
		} else {
			return archiveSize, decompressedSize, err
		}
	} else {
		return archiveSize, decompressedSize, fmt.Errorf("unsupported artifact format")
	}

	return archiveSize, decompressedSize, nil
}

func GetRemoteUpgradeSize(ctx context.Context, config *artifact.Config, uri string, upgradeDetails *details.Details) (uint64, uint64, error) {
	decompressedSize := fallbackPayloadSize
	archiveSize := fallbackArchiveSize

	var getPayloadSize func(uri string, archiveSize uint64, readRange readRangeFunc) (uint64, error)
	if strings.HasSuffix(uri, ".tar.gz") {
		getPayloadSize = getGzipPayloadSize
	} else if strings.HasSuffix(uri, ".zip") {
		getPayloadSize = getZipPayloadSize
	} else {
		return archiveSize, decompressedSize, fmt.Errorf("unsupported artifact format")
	}

	client, err := config.Client(
		httpcommon.WithAPMHTTPInstrumentation(),
		httpcommon.WithKeepaliveSettings{Disable: false, IdleConnTimeout: 30 * time.Second},
		httpcommon.WithModRoundtripper(func(rt http.RoundTripper) http.RoundTripper {
			return download.WithHeaders(rt, download.Headers)
		}),
	)
	if err != nil {
		return archiveSize, decompressedSize, err
	}

	cancelDeadline := time.Now().Add(config.Timeout)
	cancelCtx, cancel := context.WithDeadline(ctx, cancelDeadline)
	defer cancel()

	upgradeDetails.SetRetryUntil(&cancelDeadline)

	expBo := backoff.NewExponentialBackOff()
	expBo.InitialInterval = config.RetrySleepInitDuration
	boCtx := backoff.WithContext(expBo, cancelCtx)

	getArchiveSizeFn := func() error {
		n, opErr := fetchHTTPArchiveSize(cancelCtx, client, uri)
		if opErr == nil {
			if n > 0 { // -1 is unknown size
				archiveSize = uint64(n)
			}
		} else if upgradeErrors.IsPermanentHTTPError(opErr) {
			return backoff.Permanent(opErr)
		}
		return opErr
	}

	getPayloadSizeFn := func() error {
		n, opErr := getPayloadSize(uri, archiveSize, func(uri string, offset, length int64) ([]byte, error) {
			return readRangeHTTP(cancelCtx, client, uri, offset, length)
		})
		if opErr == nil {
			decompressedSize = n
		} else if upgradeErrors.IsPermanentHTTPError(opErr) {
			return backoff.Permanent(opErr)
		}
		return opErr
	}

	opFailureNotificationFn := func(err error, _ time.Duration) {
		upgradeDetails.SetRetryableError(err)
	}

	if err := backoff.RetryNotify(getArchiveSizeFn, boCtx, opFailureNotificationFn); err != nil {
		return archiveSize, decompressedSize, err
	}
	if err := backoff.RetryNotify(getPayloadSizeFn, boCtx, opFailureNotificationFn); err != nil {
		return archiveSize, decompressedSize, err
	}

	upgradeDetails.SetRetryableError(nil)
	upgradeDetails.SetRetryUntil(nil)

	return archiveSize, decompressedSize, nil
}

func readRangeHTTP(ctx context.Context, client *http.Client, uri string, offset, length int64) ([]byte, error) {
	data := make([]byte, length)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(err, fmt.Sprintf("fetching %s failed", uri), errors.TypeNetwork, errors.M(errors.MetaKeyURI, uri))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		err := errors.New(fmt.Sprintf("fetching %q returned unsuccessful status code: %d", uri, resp.StatusCode), errors.TypeNetwork, errors.M(errors.MetaKeyURI, uri))
		switch resp.StatusCode {
		case http.StatusOK:
			// 200 response to a range request means the server does not
			// support range requests
			return nil, goerrors.Join(
				fmt.Errorf("server does not support range requests for %q", uri),
				upgradeErrors.ErrPermanentHTTP)
		case http.StatusRequestedRangeNotSatisfiable:
			// Server supports range requests but archive is smaller than
			// its reported size indicated. This shouldn't happen
			return nil, goerrors.Join(
				fmt.Errorf("requested byte range %d-%d of %q is out of range", offset, offset+length-1, uri),
				upgradeErrors.ErrPermanentHTTP)
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusGone:
			return nil, goerrors.Join(err, upgradeErrors.ErrPermanentHTTP)
		}
		return nil, err
	}

	if _, err := io.ReadFull(resp.Body, data); err != nil {
		return nil, err
	}
	return data, nil
}

func getGzipPayloadSize(uri string, archiveSize uint64, readRange readRangeFunc) (uint64, error) {
	if archiveSize < 4 {
		return 0, fmt.Errorf("could not fetch gzip ISIZE: resource is only %d bytes", archiveSize)
	}
	// The gzip ISIZE is stored in the last 4 bytes.
	if archiveSize-4 > uint64(math.MaxInt64) {
		return 0, fmt.Errorf("could not fetch gzip ISIZE: archive size %d overflows int64 offset", archiveSize)
	}
	data, err := readRange(uri, int64(archiveSize-4), 4)
	if err != nil {
		return 0, fmt.Errorf("could not fetch gzip ISIZE: %w", err)
	}

	return uint64(binary.LittleEndian.Uint32(data)), nil
}

func getZipPayloadSize(uri string, archiveSize uint64, readRange readRangeFunc) (uint64, error) {
	// Zip EOCD is in the last 22 bytes. Elastic artifacts have no archive
	// comments, so read zip EOCD from the last 22 bytes.
	if archiveSize < 22 {
		return 0, fmt.Errorf("could not fetch zip EOCD: resource is only %d bytes", archiveSize)
	}
	if archiveSize-22 > uint64(math.MaxInt64) {
		return 0, fmt.Errorf("could not fetch zip EOCD: archive size %d overflows int64 offset", archiveSize)
	}
	eocd, err := readRange(uri, int64(archiveSize-22), 22)
	if err != nil {
		return 0, fmt.Errorf("could not fetch zip EOCD: %w", err)
	}
	if eocd[0] != 'P' || eocd[1] != 'K' || eocd[2] != 0x05 || eocd[3] != 0x06 {
		return 0, fmt.Errorf("could not fetch zip EOCD: missing or invalid")
	}

	cdSize := binary.LittleEndian.Uint32(eocd[12:16])
	cdOffset := binary.LittleEndian.Uint32(eocd[16:20])

	cdData, err := readRange(uri, int64(cdOffset), int64(cdSize))
	if err != nil {
		return 0, fmt.Errorf("could not fetch zip central directory: %w", err)
	}

	var total uint64
	for pos := 0; pos+46 <= len(cdData); {
		if cdData[pos] != 'P' || cdData[pos+1] != 'K' || cdData[pos+2] != 0x01 || cdData[pos+3] != 0x02 {
			break
		}
		total += uint64(binary.LittleEndian.Uint32(cdData[pos+24 : pos+28]))
		pos += 46 +
			int(binary.LittleEndian.Uint16(cdData[pos+28:pos+30])) + // file name length
			int(binary.LittleEndian.Uint16(cdData[pos+30:pos+32])) + // extra field length
			int(binary.LittleEndian.Uint16(cdData[pos+32:pos+34])) // comment length
	}
	return total, nil
}

func fetchHTTPArchiveSize(ctx context.Context, client *http.Client, uri string) (int64, error) {
	if download.IsLocal(uri) {
		path := strings.TrimPrefix(uri, "file://")
		info, err := os.Stat(path)
		if err != nil {
			return 0, fmt.Errorf("could not stat %s: %w", path, err)
		}
		return info.Size(), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, uri, nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, errors.New(err, fmt.Sprintf("fetching %s failed", uri), errors.TypeNetwork, errors.M(errors.MetaKeyURI, uri))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := errors.New(fmt.Sprintf("fetching %q returned unsuccessful status code: %d", uri, resp.StatusCode), errors.TypeNetwork, errors.M(errors.MetaKeyURI, uri))
		switch resp.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusGone:
			return 0, goerrors.Join(err, upgradeErrors.ErrPermanentHTTP)
		}
		return 0, err
	}
	if resp.ContentLength < 0 {
		return 0, fmt.Errorf("could not fetch content length for %s: server did not return a content length", uri)
	}

	return resp.ContentLength, nil
}
