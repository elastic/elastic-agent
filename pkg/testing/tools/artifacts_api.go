package tools

const defaultArtifactAPIURL = "https://artifacts-api.elastic.co"

const artifactsAPIV1VersionsEndpoint = "v1/versions/"
const artifactsAPIV1VersionBuildsEndpoint = "v1/versions/%s/builds/"
const artifactAPIV1BuildDetailsEndpoint = "v1/versions/%s/builds/%s"
const artifactAPIV1SearchVersionPackage = "v1/search/%s/%s"

type VersionList struct {
	Versions  []string `json:"versions"`
	Aliases   []string `json:"aliases"`
	Manifests struct {
		LastUpdateTime         string `json:"last-update-time"`
		SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
	} `json:"manifests"`
}

type VersionBuilds struct {
	Builds    []string `json:"builds"`
	Manifests struct {
		LastUpdateTime         string `json:"last-update-time"`
		SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
	} `json:"manifests"`
}

type Package struct {
	URL        string `json:"url"`
	ShaURL     string `json:"sha_url"`
	AscURL     string `json:"asc_url"`
	Type       string `json:"type"`
	Attributes struct {
		ArtifactNoKpi string `json:"artifactNoKpi"`
		Internal      string `json:"internal"`
		ArtifactID    string `json:"artifact_id"`
		Oss           string `json:"oss"`
		Group         string `json:"group"`
	} `json:"attributes"`
}

type Project struct {
	Branch                       string             `json:"branch"`
	CommitHash                   string             `json:"commit_hash"`
	CommitURL                    string             `json:"commit_url"`
	ExternalArtifactsManifestURL string             `json:"external_artifacts_manifest_url"`
	BuildDurationSeconds         int                `json:"build_duration_seconds"`
	Packages                     map[string]Package `json:"packages"`
	Dependencies                 []any              `json:"dependencies"`
}

type BuildDetails struct {
	Build struct {
		Projects             map[string]Project `json:"projects"`
		StartTime            string             `json:"start_time"`
		ReleaseBranch        string             `json:"release_branch"`
		Prefix               string             `json:"prefix"`
		EndTime              string             `json:"end_time"`
		ManifestVersion      string             `json:"manifest_version"`
		Version              string             `json:"version"`
		Branch               string             `json:"branch"`
		BuildID              string             `json:"build_id"`
		BuildDurationSeconds int                `json:"build_duration_seconds"`
	} `json:"build"`
	Manifests struct {
		LastUpdateTime         string `json:"last-update-time"`
		SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
	} `json:"manifests"`
}

type SearchPackageResult struct {
	Packages  map[string]Package `json:"packages"`
	Manifests struct {
		LastUpdateTime         string `json:"last-update-time"`
		SecondsSinceLastUpdate int    `json:"seconds-since-last-update"`
	} `json:"manifests"`
}
