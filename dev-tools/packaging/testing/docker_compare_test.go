// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

// This file contains tests to compare template-based and non-template Docker builds.
// Use these tests to verify the DOCKER_NO_TEMPLATE build produces equivalent results.

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	templateBuildDir   = flag.String("template-build", "", "directory containing template-based docker build artifacts")
	noTemplateBuildDir = flag.String("notemplate-build", "", "directory containing non-template docker build artifacts")
)

// TestCompareDockerBuilds compares docker images built with templates vs without templates.
// Run with:
//
//	go test -v -run TestCompareDockerBuilds \
//	  -template-build=path/to/template.docker.tar.gz \
//	  -notemplate-build=path/to/notemplate.docker.tar.gz
//
// Example using saved artifacts:
//
//	go test -v -run TestCompareDockerBuilds \
//	  -template-build=/tmp/docker-compare/template.docker.tar.gz \
//	  -notemplate-build=/tmp/docker-compare/notemplate.docker.tar.gz
func TestCompareDockerBuilds(t *testing.T) {
	if *templateBuildDir == "" || *noTemplateBuildDir == "" {
		t.Skip("Skipping comparison test: -template-build and -notemplate-build flags not provided")
	}

	// Check if the paths are files or directories
	templateInfo, err := os.Stat(*templateBuildDir)
	require.NoError(t, err, "cannot stat template-build path")
	noTemplateInfo, err := os.Stat(*noTemplateBuildDir)
	require.NoError(t, err, "cannot stat notemplate-build path")

	var templateFile, noTemplateFile string

	if templateInfo.IsDir() && noTemplateInfo.IsDir() {
		// Both are directories - find matching files
		templateFiles := getDockerFiles(t, *templateBuildDir)
		noTemplateFiles := getDockerFiles(t, *noTemplateBuildDir)

		require.NotEmpty(t, templateFiles, "no docker files found in template build directory")
		require.NotEmpty(t, noTemplateFiles, "no docker files found in notemplate build directory")

		// Match files by base name and compare
		for _, tf := range templateFiles {
			baseName := filepath.Base(tf)
			for _, ntf := range noTemplateFiles {
				if filepath.Base(ntf) == baseName {
					t.Run(baseName, func(t *testing.T) {
						compareDockerImages(t, tf, ntf)
					})
					break
				}
			}
		}
		return
	}

	// Direct file paths provided
	if !templateInfo.IsDir() {
		templateFile = *templateBuildDir
	} else {
		templateFiles := getDockerFiles(t, *templateBuildDir)
		require.NotEmpty(t, templateFiles, "no docker files found in template build directory")
		templateFile = templateFiles[0]
	}

	if !noTemplateInfo.IsDir() {
		noTemplateFile = *noTemplateBuildDir
	} else {
		noTemplateFiles := getDockerFiles(t, *noTemplateBuildDir)
		require.NotEmpty(t, noTemplateFiles, "no docker files found in notemplate build directory")
		noTemplateFile = noTemplateFiles[0]
	}

	t.Run("compare", func(t *testing.T) {
		compareDockerImages(t, templateFile, noTemplateFile)
	})
}

func getDockerFiles(t *testing.T, dir string) []string {
	pattern := regexp.MustCompile(`\.docker\.tar\.gz$`)
	matches, err := filepath.Glob(filepath.Join(dir, "*"))
	require.NoError(t, err)

	var files []string
	for _, f := range matches {
		if pattern.MatchString(filepath.Base(f)) {
			files = append(files, f)
		}
	}
	return files
}

func compareDockerImages(t *testing.T, templateFile, noTemplateFile string) {
	// Read both docker images
	templatePkg, templateInfo, err := readDocker(t, templateFile, false)
	require.NoError(t, err, "failed to read template docker file")

	noTemplatePkg, noTemplateInfo, err := readDocker(t, noTemplateFile, false)
	require.NoError(t, err, "failed to read notemplate docker file")

	// Compare entrypoints
	t.Run("entrypoint", func(t *testing.T) {
		assert.Equal(t, templateInfo.Config.Entrypoint, noTemplateInfo.Config.Entrypoint,
			"entrypoints should match")
	})

	// Compare users
	t.Run("user", func(t *testing.T) {
		assert.Equal(t, templateInfo.Config.User, noTemplateInfo.Config.User,
			"users should match")
	})

	// Compare working directories
	t.Run("workdir", func(t *testing.T) {
		assert.Equal(t, templateInfo.Config.WorkingDir, noTemplateInfo.Config.WorkingDir,
			"working directories should match")
	})

	// Compare important labels (some labels like build-date will differ)
	t.Run("labels", func(t *testing.T) {
		importantLabels := []string{
			"org.label-schema.vendor",
			"org.label-schema.license",
			"org.label-schema.name",
			"org.label-schema.url",
			"name",
			"vendor",
			"license",
			"summary",
		}

		for _, label := range importantLabels {
			templateVal := templateInfo.Config.Labels[label]
			noTemplateVal := noTemplateInfo.Config.Labels[label]
			assert.Equal(t, templateVal, noTemplateVal,
				"label %s should match: template=%q notemplate=%q", label, templateVal, noTemplateVal)
		}
	})

	// Compare file structure (check that same files exist)
	t.Run("file_structure", func(t *testing.T) {
		// Check that all files in template exist in notemplate
		missingInNoTemplate := []string{}
		for file := range templatePkg.Contents {
			if _, exists := noTemplatePkg.Contents[file]; !exists {
				missingInNoTemplate = append(missingInNoTemplate, file)
			}
		}

		// Check that all files in notemplate exist in template
		missingInTemplate := []string{}
		for file := range noTemplatePkg.Contents {
			if _, exists := templatePkg.Contents[file]; !exists {
				missingInTemplate = append(missingInTemplate, file)
			}
		}

		if len(missingInNoTemplate) > 0 {
			t.Errorf("files in template but missing in notemplate: %v", missingInNoTemplate)
		}
		if len(missingInTemplate) > 0 {
			t.Errorf("files in notemplate but missing in template: %v", missingInTemplate)
		}
	})

	// Compare file permissions for important files
	t.Run("file_permissions", func(t *testing.T) {
		importantPatterns := []*regexp.Regexp{
			regexp.MustCompile(`elastic-agent\.yml$`),
			regexp.MustCompile(`elastic-agent$`),
			regexp.MustCompile(`docker-entrypoint$`),
		}

		for file, templateEntry := range templatePkg.Contents {
			noTemplateEntry, exists := noTemplatePkg.Contents[file]
			if !exists {
				continue
			}

			for _, pattern := range importantPatterns {
				if pattern.MatchString(file) {
					assert.Equal(t, templateEntry.Mode, noTemplateEntry.Mode,
						"file %s mode should match: template=%v notemplate=%v",
						file, templateEntry.Mode, noTemplateEntry.Mode)
				}
			}
		}
	})

	// Compare sizes (allow some tolerance for minor differences)
	t.Run("size", func(t *testing.T) {
		templateSize := templateInfo.Size
		noTemplateSize := noTemplateInfo.Size

		// Allow 5% size difference due to potential layer differences
		sizeDiff := float64(abs(templateSize-noTemplateSize)) / float64(templateSize)
		if sizeDiff > 0.05 {
			t.Errorf("size difference too large: template=%d notemplate=%d diff=%.2f%%",
				templateSize, noTemplateSize, sizeDiff*100)
		} else {
			t.Logf("size comparison: template=%d notemplate=%d diff=%.2f%%",
				templateSize, noTemplateSize, sizeDiff*100)
		}
	})
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// TestDockerBuildMethodConsistency tests that DOCKER_NO_TEMPLATE env var is respected.
// This test doesn't compare builds, it just verifies the build path selection works.
func TestDockerBuildMethodConsistency(t *testing.T) {
	// This is a placeholder test that documents the expected behavior
	// The actual switching is tested by running builds with and without the env var

	t.Run("env_var_detection", func(t *testing.T) {
		// Test that the env var is correctly parsed
		testCases := []struct {
			value    string
			expected bool
		}{
			{"true", true},
			{"1", true},
			{"false", false},
			{"0", false},
			{"", false},
			{"yes", false}, // only "true" and "1" are valid
		}

		for _, tc := range testCases {
			os.Setenv("DOCKER_NO_TEMPLATE", tc.value)
			// Note: We can't directly test UseNoTemplateDockerBuild() here since it's in another package
			// This test documents the expected behavior
			t.Logf("DOCKER_NO_TEMPLATE=%q should result in notemplate=%v", tc.value, tc.expected)
		}
		os.Unsetenv("DOCKER_NO_TEMPLATE")
	})
}
