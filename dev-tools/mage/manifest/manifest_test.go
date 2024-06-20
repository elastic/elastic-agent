package manifest

import (
	"encoding/json"
	"log"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/stretchr/testify/assert"
)

// Helper to get the absolute path of the parent directory name of the current file
func ParentDir() string {
	_, filename, _, _ := runtime.Caller(1)
	return path.Dir(filename)
}

func getManifestJsonData(t *testing.T, filePath string) tools.Build {
	var response tools.Build

	contents, err := os.Open(filePath)
	assert.NoError(t, err)

	err = json.NewDecoder(contents).Decode(&response)
	assert.NoError(t, err)

	return response
}

func TestBlah(t *testing.T) {
	parentDir := ParentDir()

	tcs := []struct {
		name            string
		filePath        string
		componentName   string
		packageName     string
		requiredPackage string
		expectedUrlList []string
	}{
		{
			name:            "Unified Release Staging 8.14 apm-server",
			filePath:        path.Join(parentDir, "test_payload", "manifest-8.14.2.json"),
			componentName:   "apm-server",
			packageName:     "apm-server",
			requiredPackage: "linux-x86_64.tar.gz",
			expectedUrlList: []string{
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/apm-server/apm-server-8.14.2-linux-x86_64.tar.gz",
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/apm-server/apm-server-8.14.2-linux-x86_64.tar.gz.sha512",
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/apm-server/apm-server-8.14.2-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:            "Unified Release Snapshot 8.14 apm-server",
			filePath:        path.Join(parentDir, "test_payload", "manifest-8.14.2-SNAPSHOT.json"),
			componentName:   "apm-server",
			packageName:     "apm-server",
			requiredPackage: "linux-x86_64.tar.gz",
			expectedUrlList: []string{
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/apm-server/apm-server-8.14.2-SNAPSHOT-linux-x86_64.tar.gz",
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/apm-server/apm-server-8.14.2-SNAPSHOT-linux-x86_64.tar.gz.sha512",
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/apm-server/apm-server-8.14.2-SNAPSHOT-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:            "Independent Agent Staging 8.14 apm-server",
			filePath:        path.Join(parentDir, "test_payload", "manifest-8.14.0+build202406201002.json"),
			componentName:   "apm-server",
			packageName:     "apm-server",
			requiredPackage: "linux-x86_64.tar.gz",
			expectedUrlList: []string{
				"https://staging.elastic.co/8.14.0-fe696c51/downloads/apm-server/apm-server-8.14.0-linux-x86_64.tar.gz",
				"https://staging.elastic.co/8.14.0-fe696c51/downloads/apm-server/apm-server-8.14.0-linux-x86_64.tar.gz.sha512",
				"https://staging.elastic.co/8.14.0-fe696c51/downloads/apm-server/apm-server-8.14.0-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:            "Unified Release Staging 8.14 endpoint-dev",
			filePath:        path.Join(parentDir, "test_payload", "manifest-8.14.2.json"),
			componentName:   "endpoint-dev",
			packageName:     "endpoint-security",
			requiredPackage: "linux-x86_64.tar.gz",
			expectedUrlList: []string{
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/endpoint-dev/endpoint-security-8.14.2-linux-x86_64.tar.gz",
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/endpoint-dev/endpoint-security-8.14.2-linux-x86_64.tar.gz.sha512",
				"https://staging.elastic.co/8.14.2-cfd42f49/downloads/endpoint-dev/endpoint-security-8.14.2-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:            "Unified Release Snapshot 8.14 endpoint-dev",
			filePath:        path.Join(parentDir, "test_payload", "manifest-8.14.2-SNAPSHOT.json"),
			componentName:   "endpoint-dev",
			packageName:     "endpoint-security",
			requiredPackage: "linux-x86_64.tar.gz",
			expectedUrlList: []string{
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/endpoint-dev/endpoint-security-8.14.2-SNAPSHOT-linux-x86_64.tar.gz",
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/endpoint-dev/endpoint-security-8.14.2-SNAPSHOT-linux-x86_64.tar.gz.sha512",
				"https://snapshots.elastic.co/8.14.2-1ceac187/downloads/endpoint-dev/endpoint-security-8.14.2-SNAPSHOT-linux-x86_64.tar.gz.asc",
			},
		},
		{
			name:            "Independent Agent Staging 8.14 endpoint-dev",
			filePath:        path.Join(parentDir, "test_payload", "manifest-8.14.0+build202406201002.json"),
			componentName:   "endpoint-dev",
			packageName:     "endpoint-security",
			requiredPackage: "linux-x86_64.tar.gz",
			// Note how the version is one patch release higher than the manifest - this is expected
			expectedUrlList: []string{
				"https://staging.elastic.co/independent-agent/8.14.1+build202406201002/downloads/endpoint-dev/endpoint-security-8.14.1-linux-x86_64.tar.gz",
				"https://staging.elastic.co/independent-agent/8.14.1+build202406201002/downloads/endpoint-dev/endpoint-security-8.14.1-linux-x86_64.tar.gz.sha512",
				"https://staging.elastic.co/independent-agent/8.14.1+build202406201002/downloads/endpoint-dev/endpoint-security-8.14.1-linux-x86_64.tar.gz.asc",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			manifestJson := getManifestJsonData(t, tc.filePath)
			log.Printf("Manifest Version: [%s]", manifestJson.Version)

			projects := manifestJson.Projects

			// Verify the component name is in the ComponentSpec
			_, ok := ComponentSpec[tc.componentName]
			assert.True(t, ok)

			urlList := resolveManifestPackage(projects[tc.componentName], tc.packageName, tc.requiredPackage, manifestJson.Version)

			assert.Len(t, urlList, 3)
			for _, url := range urlList {
				assert.Contains(t, tc.expectedUrlList, url)
			}
		})
	}
}
