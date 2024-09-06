// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package downloads

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/cenkalti/backoff/v4"
	"go.elastic.co/apm/v2"
)

// BeatsLocalPath is the path to a local copy of the Beats git repository
// It can be overridden by BEATS_LOCAL_PATH env var. Using the empty string as a default.
// Deprecated. This variable will be removed in following releases, so it's not used anywhere else
var BeatsLocalPath = ""

// to avoid downloading the same artifacts, we are adding this map to cache the URL of the downloaded binaries, using as key
// the URL of the artifact. If another installer is trying to download the same URL, it will return the location of the
// already downloaded artifact.
var binariesCache = map[string]string{}
var binariesMutex sync.RWMutex

// to avoid fetching the same Elastic artifacts version, we are adding this map to cache the version of the Elastic artifacts,
// using as key the URL of the version. If another request is trying to fetch the same URL, it will return the string version
// of the already requested one.
var elasticVersionsCache = map[string]string{}
var elasticVersionsMutex sync.RWMutex

// GithubCommitSha1 represents the value of the "GITHUB_CHECK_SHA1" environment variable
var GithubCommitSha1 string

// GithubRepository represents the value of the "GITHUB_CHECK_REPO" environment variable
// Default is "elastic-agent"
var GithubRepository string = "elastic-agent"

// The compiled version of the regex created at init() is cached here so it
// only needs to be created once.
var versionAliasRegex *regexp.Regexp

func init() {
	BeatsLocalPath = getEnv("BEATS_LOCAL_PATH", BeatsLocalPath)
	if BeatsLocalPath != "" {
		logger.Warn(`⚠️ Beats local path usage is deprecated and not used to fetch the local binaries anymore. Please use the packaging job to generate the artifacts to be consumed by these tests.`)
	}

	versionAliasRegex = regexp.MustCompile(`^([0-9]+)(\.[0-9]+)(-SNAPSHOT)?$`)
}

// elasticVersion represents a version
type elasticVersion struct {
	Version         string // 8.0.0
	FullVersion     string // 8.0.0-abcdef-SNAPSHOT
	HashedVersion   string // 8.0.0-abcdef
	SnapshotVersion string // 8.0.0-SNAPSHOT
}

func newElasticVersion(version string) *elasticVersion {
	aliasMatch := versionAliasRegex.FindStringSubmatch(version)
	if aliasMatch != nil {
		v, err := GetElasticArtifactVersion(version)
		if err != nil {
			logger.Error("Failed to get version",
				slog.String("error", err.Error()),
				slog.String("version", version),
			)
			return nil
		}
		version = v
	} else {
		logger.Log(context.Background(), TraceLevel, "Version is not an alias.", slog.String("version", version))
	}

	versionWithoutCommit := RemoveCommitFromSnapshot(version)
	versionWithoutSnapshot := strings.ReplaceAll(version, "-SNAPSHOT", "")
	versionWithoutCommitAndSnapshot := strings.ReplaceAll(versionWithoutCommit, "-SNAPSHOT", "")

	return &elasticVersion{
		FullVersion:     version,
		HashedVersion:   versionWithoutSnapshot,
		SnapshotVersion: versionWithoutCommit,
		Version:         versionWithoutCommitAndSnapshot,
	}
}

// CheckPRVersion returns a fallback version if the version comes from a commit
func CheckPRVersion(version string, fallbackVersion string) string {
	if GithubCommitSha1 != "" {
		return fallbackVersion
	}

	return version
}

// FetchElasticArtifact fetches an artifact from the right repository, returning binary name, path and error
func FetchElasticArtifact(ctx context.Context, artifact string, version string, os string, arch string, extension string, isDocker bool, xpack bool) (string, string, error) {
	useCISnapshots := GithubCommitSha1 != ""

	return FetchElasticArtifactForSnapshots(ctx, useCISnapshots, artifact, version, os, arch, extension, isDocker, xpack)
}

// FetchElasticArtifactForSnapshots fetches an artifact from the right repository, returning binary name, path and error
func FetchElasticArtifactForSnapshots(ctx context.Context, useCISnapshots bool, artifact string, version string, os string, arch string, extension string, isDocker bool, xpack bool) (string, string, error) {
	binaryName := buildArtifactName(artifact, version, os, arch, extension, isDocker)
	binaryPath, err := FetchProjectBinaryForSnapshots(ctx, useCISnapshots, artifact, binaryName, artifact, version, timeoutFactor, xpack, "", false)
	if err != nil {
		logger.Error("Could not download the binary for the Elastic artifact",
			slog.String("artifact", artifact),
			slog.String("version", version),
			slog.String("os", os),
			slog.String("arch", arch),
			slog.String("extension", extension),
			slog.String("error", err.Error()),
		)
		return "", "", err
	}

	return binaryName, binaryPath, nil
}

// GetCommitVersion returns a version including the version and the git commit, if it exists
func GetCommitVersion(version string) string {
	return newElasticVersion(version).HashedVersion
}

// GetElasticArtifactURL returns the URL of a released artifact, which its full name is defined in the first argument,
// from Elastic's artifact repository, building the JSON path query based on the full name
// It also returns the URL of the sha512 file of the released artifact.
// i.e. GetElasticArtifactURL("elastic-agent-$VERSION-$ARCH.deb", "elastic-agent", "$VERSION")
// i.e. GetElasticArtifactURL("elastic-agent-$VERSION-x86_64.rpm", "elastic-agent","$VERSION")
// i.e. GetElasticArtifactURL("elastic-agent-$VERSION-linux-$ARCH.tar.gz", "elastic-agent","$VERSION")
func GetElasticArtifactURL(artifactName string, artifact string, version string) (string, string, error) {
	resolver := NewArtifactURLResolver(artifactName, artifact, version)
	if resolver == nil {
		return "", "", errors.New("nil resolver returned")
	}
	return resolver.Resolve()
}

// GetElasticArtifactVersion returns the current version:
// 1. Elastic's artifact repository, building the JSON path query based
// If the version is a SNAPSHOT including a commit, then it will directly use the version without checking the artifacts API
// i.e. GetElasticArtifactVersion("$VERSION-abcdef-SNAPSHOT")
func GetElasticArtifactVersion(version string) (string, error) {
	cacheKey := fmt.Sprintf("https://artifacts-api.elastic.co/v1/versions/%s/?x-elastic-no-kpi=true", version)

	elasticVersionsMutex.RLock()
	val, ok := elasticVersionsCache[cacheKey]
	elasticVersionsMutex.RUnlock()
	if ok {
		logger.Debug("Retrieving version from local cache",
			slog.String("URL", cacheKey),
			slog.String("version", val),
		)
		return val, nil
	}

	if SnapshotHasCommit(version) {
		elasticVersionsMutex.Lock()
		elasticVersionsCache[cacheKey] = version
		elasticVersionsMutex.Unlock()
		return version, nil
	}

	exp := getExponentialBackoff(time.Minute)

	body := []byte{}

	apiStatus := func() error {
		url := cacheKey
		r := httpRequest{URL: url}
		bodyStr, err := get(r)
		if err != nil {
			return fmt.Errorf("error getting %s: %w", url, err)
		}

		body = []byte(bodyStr)
		return nil
	}

	err := backoff.Retry(apiStatus, exp)
	if err != nil {
		return "", err
	}

	jsonParsed, err := gabs.ParseJSON(body)
	if err != nil {
		return "", fmt.Errorf("parsing JSON body %s: %w", body, err)
	}

	builds := jsonParsed.Path("version.builds")

	lastBuild := builds.Children()[0]
	latestVersion := lastBuild.Path("version").Data().(string)

	logger.Debug("Latest version for current version obtained",
		slog.String("alias", version),
		slog.String("version", latestVersion),
	)

	elasticVersionsMutex.Lock()
	elasticVersionsCache[cacheKey] = latestVersion
	elasticVersionsMutex.Unlock()

	return latestVersion, nil
}

// GetFullVersion returns a version including the full version: version, git commit and snapshot
func GetFullVersion(version string) string {
	return newElasticVersion(version).FullVersion
}

// GetSnapshotVersion returns a version including the snapshot version: version and snapshot
func GetSnapshotVersion(version string) string {
	return newElasticVersion(version).SnapshotVersion
}

// GetVersion returns a version without snapshot or commit
func GetVersion(version string) string {
	return newElasticVersion(version).Version
}

// IsAlias checks if the passed version is an alias: ex. 8.2-SNAPSHOT
func IsAlias(version string) bool {
	aliasMatch := versionAliasRegex.FindStringSubmatch(version)
	return aliasMatch != nil
}

// RemoveCommitFromSnapshot removes the commit from a version including commit and SNAPSHOT
func RemoveCommitFromSnapshot(s string) string {
	// regex = X.Y.Z-commit-SNAPSHOT
	re := regexp.MustCompile(`-\b[0-9a-f]{5,40}\b`)

	return re.ReplaceAllString(s, "")
}

func ExtractCommitHash(input string) (string, error) {
	re := regexp.MustCompile(`-(\w+)-`)
	matches := re.FindStringSubmatch(input)

	if len(matches) < 2 {
		return "", fmt.Errorf("commit hash not found")
	}

	return matches[1], nil
}

// SnapshotHasCommit returns true if the snapshot version contains a commit format
func SnapshotHasCommit(s string) bool {
	// regex = X.Y.Z-commit-SNAPSHOT
	re := regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-\b[0-9a-f]{5,40}\b)(-SNAPSHOT)`)

	return re.MatchString(s)
}

// UseBeatsCISnapshots check if CI snapshots should be used for the Beats, where the given SHA commit
// lives in the beats repository
func UseBeatsCISnapshots() bool {
	return useCISnapshots("beats")
}

// UseElasticAgentCISnapshots check if CI snapshots should be used for the Elastic Agent, where the given SHA commit
// lives in the elastic-agent repository
func UseElasticAgentCISnapshots() bool {
	return useCISnapshots("elastic-agent")
}

// useCISnapshots check if CI snapshots should be used, passing a function that evaluates the repository in which
// the given Sha commit has context. I.e. a commit in the elastic-agent repository should pass a function that
func useCISnapshots(repository string) bool {
	logger.Log(context.Background(), TraceLevel, "Use CI Snapshot",
		slog.String("repository", repository),
		slog.String("gitRepo", GithubRepository),
		slog.String("gitSha1", GithubCommitSha1),
	)

	if GithubCommitSha1 != "" && strings.EqualFold(GithubRepository, repository) {
		return true
	}
	return false
}

// buildArtifactName builds the artifact name from the different coordinates for the artifact
func buildArtifactName(artifact string, artifactVersion string, OS string, arch string, extension string, isDocker bool) string {
	dockerString := ""

	lowerCaseExtension := strings.ToLower(extension)
	artifactVersion = GetSnapshotVersion(artifactVersion)

	useCISnapshots := GithubCommitSha1 != ""

	if isDocker {
		// we detected that the docker name on CI is using a different structure
		// CI snapshots on GCP: elastic-agent-$VERSION-linux-$ARCH.docker.tar.gz
		// Elastic's snapshots: elastic-agent-$VERSION-docker-image-linux-$ARCH.tar.gz
		dockerString = ".docker"
		if !useCISnapshots {
			dockerString = "-docker-image"
		}
	}

	if !useCISnapshots && isDocker {
		return fmt.Sprintf("%s-%s%s-%s-%s.%s", artifact, artifactVersion, dockerString, OS, arch, lowerCaseExtension)
	}

	if lowerCaseExtension == "deb" || lowerCaseExtension == "rpm" {
		return fmt.Sprintf("%s-%s-%s%s.%s", artifact, artifactVersion, arch, dockerString, lowerCaseExtension)
	}

	return fmt.Sprintf("%s-%s-%s-%s%s.%s", artifact, artifactVersion, OS, arch, dockerString, lowerCaseExtension)
}

// FetchBeatsBinary it downloads the binary and returns the location of the downloaded file
// If the environment variable BEATS_LOCAL_PATH is set, then the artifact
// to be used will be defined by the local snapshot produced by the local build.
// Else, if the environment variable GITHUB_CHECK_SHA1 is set, then the artifact
// to be downloaded will be defined by the snapshot produced by the Beats CI for that commit.
func FetchBeatsBinary(ctx context.Context, artifactName string, artifact string, version string, timeoutFactor int, xpack bool, downloadPath string, downloadSHAFile bool) (string, error) {
	return FetchProjectBinary(ctx, "beats", artifactName, artifact, version, timeoutFactor, xpack, downloadPath, downloadSHAFile)
}

// FetchProjectBinary it downloads the binary and returns the location of the downloaded file
// If the environment variable BEATS_LOCAL_PATH is set, then the artifact
// to be used will be defined by the local snapshot produced by the local build.
// Else, if the environment variable GITHUB_CHECK_SHA1 is set, then the artifact
// to be downloaded will be defined by the snapshot produced by the Beats CI for that commit.
func FetchProjectBinary(ctx context.Context, project string, artifactName string, artifact string, version string, timeoutFactor int, xpack bool, downloadPath string, downloadSHAFile bool) (string, error) {
	useCISnapshots := GithubCommitSha1 != ""

	return FetchProjectBinaryForSnapshots(ctx, useCISnapshots, project, artifactName, artifact, version, timeoutFactor, xpack, downloadPath, downloadSHAFile)
}

// FetchProjectBinaryForSnapshots it downloads the binary and returns the location of the downloaded file
// If the deprecated environment variable BEATS_LOCAL_PATH is set, then an error will be returned.
// Else, if the useCISnapshots argument is set to true, then the artifact
// to be downloaded will be defined by the snapshot produced by the Beats CI or Fleet CI for that commit.
func FetchProjectBinaryForSnapshots(ctx context.Context, useCISnapshots bool, project string, artifactName string, artifact string, version string, timeoutFactor int, xpack bool, downloadPath string, downloadSHAFile bool) (string, error) {
	if BeatsLocalPath != "" {
		return "", fmt.Errorf("⚠️ Beats local path usage is deprecated and not used to fetch the binaries. Please use the packaging job to generate the artifacts to be consumed by these tests")
	}

	handleDownload := func(URL string) (string, error) {
		name := artifactName
		downloadRequest := downloadRequest{
			DownloadPath: downloadPath,
			URL:          URL,
		}
		span, _ := apm.StartSpanOptions(ctx, "Fetching Project binary", "project.url.fetch-binary", apm.SpanOptions{
			Parent: apm.SpanFromContext(ctx).TraceContext(),
		})
		span.Context.SetLabel("project", project)
		defer span.End()

		binariesMutex.RLock()
		val, ok := binariesCache[URL]
		binariesMutex.RUnlock()
		if ok {
			logger.Debug("Retrieving binary from local cache",
				slog.String("URL", URL),
				slog.String("path", val),
			)
			return val, nil
		}

		err := downloadFile(&downloadRequest)
		if err != nil {
			return downloadRequest.UnsanitizedFilePath, err
		}

		if strings.HasSuffix(URL, ".sha512") {
			name = fmt.Sprintf("%s.sha512", name)
		}
		// use artifact name as file name to avoid having URL params in the name
		sanitizedFilePath := filepath.Join(path.Dir(downloadRequest.UnsanitizedFilePath), name)
		err = os.Rename(downloadRequest.UnsanitizedFilePath, sanitizedFilePath)
		if err != nil {
			logger.Warn("Could not sanitize downloaded file name. Keeping old name",
				slog.String("fileName", downloadRequest.UnsanitizedFilePath),
				slog.String("sanitizedFileName", sanitizedFilePath),
			)
			sanitizedFilePath = downloadRequest.UnsanitizedFilePath
		}

		binariesMutex.Lock()
		binariesCache[URL] = sanitizedFilePath
		binariesMutex.Unlock()

		return sanitizedFilePath, nil
	}

	var downloadURL, downloadShaURL string
	var err error

	if useCISnapshots {
		span, _ := apm.StartSpanOptions(ctx, "Fetching Beats binary", "beats.gcp.fetch-binary", apm.SpanOptions{
			Parent: apm.SpanFromContext(ctx).TraceContext(),
		})
		defer span.End()

		logger.Debug(fmt.Sprintf("Using CI snapshots for %s", artifact))

		maxTimeout := time.Duration(timeoutFactor) * time.Minute

		variant := ""
		if strings.HasSuffix(artifact, "-ubi8") {
			variant = "ubi8"
		}

		// look up the bucket in this particular order:
		// 1. the project layout (elastic-agent, fleet-server)
		// 2. the new beats layout (beats)
		// 3. the legacy Beats layout (commits/snapshots)
		resolvers := []BucketURLResolver{
			NewProjectURLResolver(FleetCIArtifactsBase, project, artifactName, variant),
			NewProjectURLResolver(BeatsCIArtifactsBase, project, artifactName, variant),
			NewBeatsURLResolver(artifact, artifactName, variant),
			NewBeatsLegacyURLResolver(artifact, artifactName, variant),
		}

		downloadURL, err = getObjectURLFromResolvers(resolvers, maxTimeout)
		if err != nil {
			return "", err
		}
		downloadLocation, err := handleDownload(downloadURL)

		// check if sha file should be downloaded, else return
		if !downloadSHAFile {
			return downloadLocation, err
		}

		sha512ArtifactName := fmt.Sprintf("%s.sha512", artifactName)

		sha512Resolvers := []BucketURLResolver{
			NewProjectURLResolver(FleetCIArtifactsBase, project, sha512ArtifactName, variant),
			NewProjectURLResolver(BeatsCIArtifactsBase, project, sha512ArtifactName, variant),
			NewBeatsURLResolver(artifact, sha512ArtifactName, variant),
			NewBeatsLegacyURLResolver(artifact, sha512ArtifactName, variant),
		}

		downloadURL, err = getObjectURLFromResolvers(sha512Resolvers, maxTimeout)
		if err != nil {
			return "", err
		}
		return handleDownload(downloadURL)
	}

	elasticAgentNamespace := project
	if strings.EqualFold(elasticAgentNamespace, "elastic-agent") {
		elasticAgentNamespace = "beats"
	}

	// look up the binaries, first checking releases, then artifacts
	downloadURLResolvers := []DownloadURLResolver{
		NewReleaseURLResolver(elasticAgentNamespace, artifactName, artifact),
		NewArtifactURLResolver(artifactName, artifact, version),
		NewArtifactSnapshotURLResolver(artifactName, artifact, project, version),
	}
	downloadURL, downloadShaURL, err = getDownloadURLFromResolvers(downloadURLResolvers)
	if err != nil {
		return "", err
	}
	fmt.Printf("Downloading from %s\n", downloadURL)
	downloadLocation, err := handleDownload(downloadURL)
	if err != nil {
		return "", err
	}
	if downloadSHAFile && downloadShaURL != "" {
		downloadLocation, err = handleDownload(downloadShaURL)
	}
	return downloadLocation, err
}

func getBucketSearchNextPageParam(jsonParsed *gabs.Container) string {
	token := jsonParsed.Path("nextPageToken")
	if token == nil {
		return ""
	}

	nextPageToken := token.Data().(string)
	return "&pageToken=" + nextPageToken
}

// getDownloadURLFromResolvers returns the URL for the desired artifacts
func getDownloadURLFromResolvers(resolvers []DownloadURLResolver) (string, string, error) {
	for i, resolver := range resolvers {
		if resolver == nil {
			continue
		}

		attr := slog.String("kind", resolver.Kind())

		logger.Info("Trying resolver.", attr)
		url, shaURL, err := resolver.Resolve()
		if err != nil {
			if i < len(resolvers)-1 {
				logger.Warn("Object not found.", attr)
				continue
			} else {
				logger.Error("Object not found. All resolvers failed", attr)
				return "", "", err
			}
		}

		return url, shaURL, nil
	}

	return "", "", fmt.Errorf("the artifact was not found")
}

// getObjectURLFromResolvers extracts the media URL for the desired artifact from the
// Google Cloud Storage bucket used by the CI to push snapshots
func getObjectURLFromResolvers(resolvers []BucketURLResolver, maxtimeout time.Duration) (string, error) {
	for i, resolver := range resolvers {
		bucket, prefix, object := resolver.Resolve()

		downloadURL, err := getObjectURLFromBucket(bucket, prefix, object, maxtimeout)
		if err != nil {
			if i < len(resolvers)-1 {
				logger.Warn("Object not found. Trying with another artifact resolver", slog.String("resolver", fmt.Sprintf("%T", resolver)))
				continue
			} else {
				logger.Error("Object not found. There is no other artifact resolver")
				return "", err
			}
		}

		return downloadURL, nil
	}

	return "", fmt.Errorf("the artifact was not found")
}

// getObjectURLFromBucket extracts the media URL for the desired artifact from the
// Google Cloud Storage bucket used by the CI to push snapshots
func getObjectURLFromBucket(bucket string, prefix string, object string, maxtimeout time.Duration) (string, error) {
	exp := getExponentialBackoff(maxtimeout)

	retryCount := 1

	currentPage := 0
	pageTokenQueryParam := ""
	mediaLink := ""

	storageAPI := func() error {
		r := httpRequest{
			URL: fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o?prefix=%s%s", bucket, prefix, pageTokenQueryParam),
		}

		response, err := get(r)
		if err != nil {
			logger.Warn("Google Cloud Storage API is not available yet",
				slog.String("bucket", bucket),
				slog.Duration("elapsedTime", exp.GetElapsedTime()),
				slog.String("prefix", prefix),
				slog.String("error", err.Error()),
				slog.String("object", object),
				slog.Int("retry", retryCount),
			)

			retryCount++

			return err
		}

		logger.Log(context.Background(), TraceLevel, "Google Cloud Storage API is available",
			slog.String("bucket", bucket),
			slog.Duration("elapsedTime", exp.GetElapsedTime()),
			slog.String("prefix", prefix),
			slog.String("object", object),
			slog.Int("retries", retryCount),
			slog.String("url", r.URL),
		)

		jsonParsed, err := gabs.ParseJSON([]byte(response))
		if err != nil {
			logger.Warn("Could not parse the response body for the object",
				slog.String("bucket", bucket),
				slog.String("prefix", prefix),
				slog.String("object", object),
			)

			retryCount++

			return err
		}

		mediaLink, err = processBucketSearchPage(jsonParsed, currentPage, bucket, prefix, object)
		if err != nil {
			logger.Warn(err.Error(),
				slog.Int("currentPage", currentPage),
				slog.String("bucket", bucket),
				slog.String("prefix", prefix),
				slog.String("object", object),
			)
		} else if mediaLink != "" {
			logger.Debug("Media link found for the object",
				slog.String("bucket", bucket),
				slog.Duration("elapsedTime", exp.GetElapsedTime()),
				slog.String("prefix", prefix),
				slog.String("medialink", mediaLink),
				slog.String("object", object),
				slog.Int("retries", retryCount),
			)
			return nil
		}

		pageTokenQueryParam = getBucketSearchNextPageParam(jsonParsed)
		if pageTokenQueryParam == "" {
			logger.Warn("Reached the end of the pages and the object was not found",
				slog.Int("currentPage", currentPage),
				slog.String("bucket", bucket),
				slog.String("prefix", prefix),
				slog.String("object", object),
			)

			return nil
		}

		currentPage++

		logger.Warn("Object not found in current page. Continuing",
			slog.Int("currentPage", currentPage),
			slog.String("bucket", bucket),
			slog.Duration("elapsedTime", exp.GetElapsedTime()),
			slog.String("prefix", prefix),
			slog.String("object", object),
			slog.Int("retries", retryCount),
		)

		return fmt.Errorf("the %s object could not be found in the current page (%d) the %s bucket and %s prefix", object, currentPage, bucket, prefix)
	}

	err := backoff.Retry(storageAPI, exp)
	if err != nil {
		return "", err
	}
	if mediaLink == "" {
		return "", fmt.Errorf("reached the end of the pages and the %s object was not found for the %s bucket and %s prefix", object, bucket, prefix)
	}

	return mediaLink, nil
}

func processBucketSearchPage(jsonParsed *gabs.Container, currentPage int, bucket string, prefix string, object string) (string, error) {
	items := jsonParsed.Path("items").Children()

	logger.Debug("Objects found",
		slog.String("bucket", bucket),
		slog.String("prefix", prefix),
		slog.Int("objects", len(items)),
		slog.String("object", object),
	)

	for _, item := range items {
		itemID := item.Path("id").Data().(string)
		objectPath := bucket + "/" + prefix + "/" + object + "/"
		if strings.HasPrefix(itemID, objectPath) {
			mediaLink := item.Path("mediaLink").Data().(string)

			logger.Info(fmt.Sprintf("medialink: %s", mediaLink))
			return mediaLink, nil
		}
	}

	return "", fmt.Errorf("the %s object could not be found in the current page (%d) in the %s bucket and %s prefix", object, currentPage, bucket, prefix)
}

// getEnv returns an environment variable as string
func getEnv(envVar string, defaultValue string) string {
	value, exists := os.LookupEnv(envVar)
	if exists && value != "" {
		return value
	}

	return defaultValue
}

// getEnvInteger returns an environment variable as integer, including a default value
func getEnvInteger(envVar string, defaultValue int) int {
	if value, exists := os.LookupEnv(envVar); exists {
		v, err := strconv.Atoi(value)
		if err == nil {
			return v
		}
	}

	return defaultValue
}
