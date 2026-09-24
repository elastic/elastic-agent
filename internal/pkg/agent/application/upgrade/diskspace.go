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
	"path/filepath"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	upgradeErrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

const (
	ChecksumSize        = uint64(1024)                   // 1KB
	ExtraInstallSize    = uint64(50 * 1024 * 1024)       // 50MB
	MarkerSize          = uint64(1024 * 1024)            // 1MB
	FallbackArchiveSize = uint64(700 * 1024 * 1024)      // 700MB
	FallbackPayloadSize = uint64(2 * 1024 * 1024 * 1024) // 2GB
)

func getArchiveReservation(archiveDir string) string {
	return filepath.Join(archiveDir, ".elastic-agent-artifact.reserved.tmp")
}

func getInstallReservation() string {
	return filepath.Join(paths.Data(), ".elastic-agent-install.reserved.tmp")
}

func formatSize(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func checkSameVolume(pathA, pathB string) bool {
	// Failures are treated as different filesystems since we only use this for
	// determining the error message to display.
	volumeA, err := getVolumeNameAt(pathA)
	if err != nil {
		return false
	}
	volumeB, err := getVolumeNameAt(pathB)
	if err != nil {
		return false
	}
	return volumeA == volumeB
}

type readRangeFunc func(uri string, offset, length int64) ([]byte, error)

// ReserveDiskSpace reserves upgrade space at the download archive path and install directory.
// Pre-existing reservation files are resized to the required size.
func ReserveDiskSpace(archiveDir string, archiveSize, decompressedSize uint64) (bool, error) {
	installSize := min(decompressedSize+ExtraInstallSize, math.MaxInt64)
	artifactsSize := min(archiveSize+ChecksumSize, math.MaxInt64)

	installPath := getInstallReservation()
	archivePath := getArchiveReservation(archiveDir)
	onSameVolume := checkSameVolume(paths.Data(), archiveDir)

	var errs []error
	var spaceReqs []string

	err := reserveDiskSpace(installPath, int64(installSize)) //nolint:gosec // G115: installSize is clamped to MaxInt64
	if upgradeErrors.IsDiskSpaceLowError(err) {
		if onSameVolume {
			// Report both requirements so the user doesn't free up just the install
			// size and then fail again on the archive reservation
			return false, upgradeErrors.DiskSpaceLowError{
				fmt.Sprintf("need %s at %s", formatSize(installSize), paths.Data()),
				fmt.Sprintf("need %s at %s", formatSize(artifactsSize), archiveDir),
			}
		}

		spaceReqs = append(spaceReqs, fmt.Sprintf("need %s at %s", formatSize(installSize), paths.Data()))
	} else if err != nil {
		errs = append(errs, err)
	}

	err = reserveDiskSpace(archivePath, int64(artifactsSize)) //nolint:gosec // G115: artifactsSize is clamped to MaxInt64
	if upgradeErrors.IsDiskSpaceLowError(err) {
		if onSameVolume {
			// Report both requirements here even though the install reservation
			// succeeded. We remove the reserved install file on upgrade failure, so
			// only reporting needing X for the archive size will be confusing
			// for the user as they aren't aware of our internal reservation
			// mechanics and it would appear as if X is already available
			errs = append(errs,
				upgradeErrors.DiskSpaceLowError{
					fmt.Sprintf("need %s at %s", formatSize(installSize), paths.Data()),
					fmt.Sprintf("need %s at %s", formatSize(artifactsSize), archiveDir),
				},
			)
			return false, goerrors.Join(errs...)
		}

		spaceReqs = append(spaceReqs, fmt.Sprintf("need %s at %s", formatSize(artifactsSize), archiveDir))
	} else if err != nil {
		errs = append(errs, err)
	}

	if len(spaceReqs) > 0 {
		errs = append(errs, upgradeErrors.DiskSpaceLowError(spaceReqs))
	}
	if errs == nil {
		return true, nil
	}

	return false, goerrors.Join(errs...)
}

func reserveDiskSpace(path string, size int64) error {
	info, statErr := os.Stat(path)
	fresh := goerrors.Is(statErr, os.ErrNotExist)

	var reservedSize int64
	if statErr == nil {
		reservedSize = info.Size()
	}
	if size > reservedSize {
		if available, err := getAvailableDiskSpaceAt(filepath.Dir(path)); err == nil {
			needed := uint64(size - reservedSize) //nolint:gosec // G115: size is greater than reservedSize
			if needed > available {
				return upgradeErrors.DiskSpaceLowError{
					fmt.Sprintf("need %s at %s, %s available", formatSize(needed), filepath.Dir(path), formatSize(available)),
				}
			}
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o660)
	if err != nil {
		return err
	}

	if err := preallocateFile(file, size); err != nil {
		_ = file.Close()
		if fresh {
			_ = os.Remove(path)
		}
		return err
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		if fresh {
			_ = os.Remove(path)
		}
		return err
	}
	if err := file.Close(); err != nil {
		if fresh {
			_ = os.Remove(path)
		}
		return err
	}
	return nil
}

func shrinkDiskSpaceReservation(path string, delta int64) error {
	info, err := os.Stat(path)
	if goerrors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("could not stat upgrade reservation file %s: %w", path, err)
	}
	size := max(info.Size()-delta, 0)
	if size >= info.Size() {
		return nil
	}
	if err := os.Truncate(path, size); err != nil {
		return fmt.Errorf("could not shrink upgrade reservation file %s: %w", path, err)
	}
	return nil
}

func getUpgradeSize(ctx context.Context, config *artifact.Config, uri string) (uint64, uint64, error) {
	var archiveSize, decompressedSize uint64
	var err error
	if download.IsLocal(uri) {
		archiveSize, decompressedSize, err = GetLocalUpgradeSize(uri)
	} else {
		archiveSize, decompressedSize, err = GetRemoteUpgradeSize(ctx, config, uri)
	}

	if err != nil {
		return archiveSize, decompressedSize, goerrors.Join(upgradeErrors.ErrFetchUpgradeSize, err)
	}
	return archiveSize, decompressedSize, nil
}

func GetLocalUpgradeSize(uri string) (uint64, uint64, error) {
	decompressedSize := FallbackPayloadSize
	archiveSize := FallbackArchiveSize

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

func GetRemoteUpgradeSize(ctx context.Context, config *artifact.Config, uri string) (uint64, uint64, error) {
	decompressedSize := FallbackPayloadSize
	archiveSize := FallbackArchiveSize

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

	n, err := fetchHTTPArchiveSize(ctx, client, uri)
	if err != nil {
		return archiveSize, decompressedSize, err
	}
	if n > 0 { // -1 is unknown size
		archiveSize = uint64(n)
	}

	payloadSize, err := getPayloadSize(uri, archiveSize, func(uri string, offset, length int64) ([]byte, error) {
		return readRangeHTTP(ctx, client, uri, offset, length)
	})
	if err != nil {
		return archiveSize, decompressedSize, err
	}
	decompressedSize = payloadSize

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
			// Server supports range requests but archive is smaller than reported
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
	// gzip ISIZE is stored in the last 4 bytes.
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
	// zip EOCD is in the last 22 bytes. Elastic artifacts have no archive
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
		return 0, goerrors.Join(
			fmt.Errorf("could not fetch content length for %s: server did not return a content length", uri),
			upgradeErrors.ErrPermanentHTTP)
	}

	return resp.ContentLength, nil
}
