// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	downloaderrors "github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

const (
	defaultRetryTimeout       = 15 * time.Minute  // stop retrying after this time
	totalTimeout              = 240 * time.Minute // max possible time spent retrying/downloading all sources
	defaultRemoteSourceSubdir = "beats/elastic-agent"
	snapshotURIFormat         = "https://snapshots.elastic.co/%s-%s/downloads/"
)

type artifactDownloader struct {
	log            *logger.Logger
	settings       *artifact.Config
	fleetServerURI string
	getPGPSources  func(log *logger.Logger, fleetServerURI string, targetVersion *agtversion.ParsedSemVer, pgpSources []string) []string
	retryTimeout   time.Duration
	totalTimeout   time.Duration
	fileOps        download.FileOps
}

func newArtifactDownloader(settings *artifact.Config, log *logger.Logger) *artifactDownloader {
	return &artifactDownloader{
		log:           log,
		settings:      settings,
		getPGPSources: download.AppendFallbackPGP,
		retryTimeout:  defaultRetryTimeout,
		totalTimeout:  totalTimeout,
		fileOps: download.FileOps{
			CopyFile: io.Copy,
			OpenFile: os.OpenFile,
		},
	}
}

func (a *artifactDownloader) withFleetServerURI(fleetServerURI string) {
	a.fleetServerURI = fleetServerURI
}

func (a *artifactDownloader) downloadArtifact(ctx context.Context, target artifact.Artifact, sources []string, upgradeDetails *details.Details, skipVerifyOverride, skipDefaultPgp bool, pgpBytes ...string) (_ string, err error) {
	span, ctx := apm.StartSpan(ctx, "downloadArtifact", "app.internal")
	defer func() {
		apm.CaptureError(ctx, err).Send()
		span.End()
	}()

	pgpBytes = a.getPGPSources(a.log, a.fleetServerURI, target.Version, pgpBytes)

	// do not update source config
	settings := *a.settings

	sources = slices.DeleteFunc(slices.Clone(sources), func(source string) bool { return source == "" })
	if len(sources) == 0 {
		configSources := slices.DeleteFunc(slices.Clone(settings.Sources), func(source string) bool { return source == "" })
		if len(configSources) > 0 {
			sources = configSources
		} else {
			sources = []string{artifact.DefaultSourceURI}
		}
	}

	checkDropPath := false
	for _, source := range sources {
		if !download.IsLocal(source) {
			checkDropPath = true
			break
		}
	}
	if checkDropPath {
		// drop path is the same for all remote sources, so insert it once before the first remote source
		firstRemoteIndex := slices.IndexFunc(sources, func(src string) bool { return !download.IsLocal(src) })
		dropURI := "file://" + settings.GetDropPath()
		if !slices.Contains(sources, dropURI) { // might be in config already
			sources = slices.Insert(sources, firstRemoteIndex, dropURI)
		}
	}

	fileName := target.FileName()
	if target.Version.IsSnapshot() {
		// Published snapshot artifacts never include the buildID in the file
		// name; it only selects the download URI for the default source. Use
		// the published name for every source so all sources are
		// interchangeable.
		fileName = strings.Replace(fileName, target.Version.String(), target.Version.VersionWithPrerelease(), 1)
	}
	targetPath := filepath.Join(settings.TargetDirectory, fileName)

	if err := os.MkdirAll(settings.TargetDirectory, 0o750); err != nil {
		return "", fmt.Errorf("failed to create target directory %s: %w", settings.TargetDirectory, err)
	}

	a.log.Infow("Getting upgrade artifact", "filename", fileName, "version", target.Version, "drop_path", settings.DropPath, "target_path", targetPath, "install_path", settings.InstallPath)

	ctx, cancel := context.WithTimeout(ctx, a.totalTimeout)
	defer cancel()

	retryTimeout := min(a.retryTimeout, settings.Timeout)
	retryDeadline := time.Now().Add(retryTimeout)
	upgradeDetails.SetRetryUntil(&retryDeadline)

	retrier := backoff.NewExponentialBackOff(
		backoff.WithInitialInterval(settings.RetrySleepInitDuration),
		backoff.WithMaxElapsedTime(retryTimeout),
	)
	retryCtx := backoff.WithContext(retrier, ctx)

	attempt := 0
	skip := make([]bool, len(sources))
	errs := make([]error, len(sources))

	fetchSources := func() error {
		for i, src := range sources {
			if skip[i] {
				continue
			}

			if target.Version.IsSnapshot() && src == artifact.DefaultSourceURI && target.Version.BuildMetadata() == "" {
				buildID, err := latestSnapshotBuildID(ctx, &settings, target.Version)
				if err != nil {
					e := fmt.Errorf("couldn't retrieve latest snapshot build ID: %w", err)
					a.log.Debugf("%v", e)
					errs[i] = e
					continue
				}

				target.Version = agtversion.NewParsedSemVer(
					target.Version.Major(),
					target.Version.Minor(),
					target.Version.Patch(),
					target.Version.Prerelease(),
					buildID,
				)
			}

			sourceURI, err := Resolve(ctx, target, src, defaultRemoteSourceSubdir, fileName)
			if err != nil {
				e := fmt.Errorf("could not resolve source %s: %w", src, err)
				a.log.Debugf("%v", e)
				errs[i] = e
				skip[i] = true
				continue
			}
			if download.IsLocal(sourceURI) {
				a.log.Infow("Copying local artifact", "source_uri", sourceURI)
			} else {
				a.log.Infow("Downloading artifact", "source_uri", sourceURI, "proxy_uri", settings.Proxy.URL, "proxy_disable", settings.Proxy.Disable)
			}

			if err = download.Fetch(ctx, a.log, &settings, upgradeDetails, sourceURI, targetPath, a.fileOps); err != nil {
				if downloaderrors.IsDiskSpaceError(err) {
					return backoff.Permanent(err)
				}
				var agentErr errors.Error
				if goerrors.As(err, &agentErr) && agentErr.Type() == errors.TypeFilesystem && !errors.Is(err, os.ErrNotExist) {
					if agentErr.Meta()[errors.MetaKeyPath] == targetPath {
						// can't write to target
						return backoff.Permanent(err)
					}
				}

				if download.IsLocal(sourceURI) {
					// don't retry local sources
					skip[i] = true
				}
				if downloaderrors.IsPermanentHTTPError(err) {
					skip[i] = true
				}

				e := fmt.Errorf("could not fetch artifact from %s: %w", src, err)
				a.log.Debugf("%v", e)
				errs[i] = e
				continue
			}

			if !skipVerifyOverride {
				if err = download.Fetch(ctx, a.log, &settings, upgradeDetails, download.AddHashExtension(sourceURI), download.AddHashExtension(targetPath), a.fileOps); err != nil {
					if downloaderrors.IsDiskSpaceError(err) {
						return backoff.Permanent(err)
					}
					var agentErr errors.Error
					if goerrors.As(err, &agentErr) && agentErr.Type() == errors.TypeFilesystem && !errors.Is(err, os.ErrNotExist) {
						if agentErr.Meta()[errors.MetaKeyPath] == download.AddHashExtension(targetPath) {
							// can't write to target
							return backoff.Permanent(err)
						}
					}

					if download.IsLocal(sourceURI) {
						// don't retry local sources
						skip[i] = true
					}
					if downloaderrors.IsPermanentHTTPError(err) {
						skip[i] = true
					}

					e := fmt.Errorf("could not fetch artifact sha512 from %s: %w", src, err)
					a.log.Debugf("%v", e)
					errs[i] = e
					continue
				}

				if err = download.Verify(ctx, a.log, &settings, release.PGP(), sourceURI, targetPath, skipDefaultPgp, pgpBytes...); err != nil {
					e := fmt.Errorf("verification failed for %s: %w", src, err)
					a.log.Debugf("%v", e)
					if !errors.IsNetworkError(err) {
						skip[i] = true
					}
					errs[i] = e
					continue
				}
			}

			return nil
		}

		attempt++
		sourceErrs := []error{}
		for i, err := range errs {
			if err != nil {
				sourceErrs = append(sourceErrs, fmt.Errorf("source %s failed: %w", sources[i], err))
			}
		}
		err := goerrors.Join(sourceErrs...)

		if !slices.Contains(skip, false) {
			// all sources exhausted
			return backoff.Permanent(err)
		}
		return err
	}

	retryFailure := func(err error, retryAfter time.Duration) {
		a.log.Warnf("artifact download attempt %d failed: %s; retrying in %s.",
			attempt, err.Error(), retryAfter)
		upgradeDetails.SetRetryableError(err)
	}

	if err := backoff.RetryNotify(fetchSources, retryCtx, retryFailure); err != nil {
		return targetPath, fmt.Errorf("failed to get upgrade artifact: %w", err)
	}

	upgradeDetails.SetRetryableError(nil)
	upgradeDetails.SetRetryUntil(nil)

	return targetPath, nil
}

// Resolve computes the fully resolved download URI for an artifact.
func Resolve(ctx context.Context, target artifact.Artifact, sourceURI, sourceSubdir, fileName string) (string, error) {
	if target.Version.IsSnapshot() && sourceURI == artifact.DefaultSourceURI {
		buildID := target.Version.BuildMetadata()
		sourceURI = fmt.Sprintf(snapshotURIFormat, target.Version.CoreVersion(), buildID)
	}

	if strings.HasPrefix(sourceURI, "/") || strings.HasPrefix(sourceURI, "file://") {
		sourcePath := filepath.Join(strings.TrimPrefix(sourceURI, "file://"), fileName)
		return "file://" + filepath.ToSlash(sourcePath), nil
	}

	if !strings.HasPrefix(sourceURI, "http://") && !strings.HasPrefix(sourceURI, "https://") {
		sourceURI = "https://" + sourceURI
	}

	uri, err := url.JoinPath(sourceURI, sourceSubdir, fileName)
	if err != nil {
		return "", errors.New(err, "invalid download source URI")
	}

	return uri, nil
}

func latestSnapshotBuildID(ctx context.Context, config *artifact.Config, version *agtversion.ParsedSemVer) (string, error) {
	client, err := config.Client(
		httpcommon.WithAPMHTTPInstrumentation(),
		httpcommon.WithModRoundtripper(func(rt http.RoundTripper) http.RoundTripper {
			return download.WithHeaders(rt, download.Headers)
		}),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP client for resolving snapshot download url: %w", err)
	}

	versionStr := version.CoreVersion()
	latestSnapshotURI := fmt.Sprintf("https://snapshots.elastic.co/latest/%s-SNAPSHOT.json", versionStr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestSnapshotURI, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request to the snapshot API: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return "", fmt.Errorf("snapshot for version %q not found", versionStr)
	case http.StatusOK:
		var info struct {
			BuildID string `json:"build_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
			return "", err
		}
		parts := strings.Split(info.BuildID, "-")
		if len(parts) != 2 {
			return "", fmt.Errorf("wrong format for a build ID: %s", info.BuildID)
		}
		return parts[1], nil
	default:
		return "", fmt.Errorf("unexpected status code %d from %s", resp.StatusCode, latestSnapshotURI)
	}
}
