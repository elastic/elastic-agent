// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func testPackageSpec(t testing.TB) PackageSpec {
	t.Helper()
	cfg, err := LoadSettings()
	require.NoError(t, err)
	return PackageSpec{
		Name:     "brewbeat",
		Version:  "7.0.0",
		Snapshot: true,
		OS:       "windows",
		Arch:     "x86_64",
		ExtraTags: []string{
			"git-{{ substring core_commit 0 12 }}",
		},
		Files: map[string]PackageFile{
			"brewbeat.yml": PackageFile{
				Source: "./testdata/config.yml",
				Mode:   0644,
			},
			"README.txt": PackageFile{
				Content: "Hello! {{.Version}}\n",
				Mode:    0644,
			},
		},
		cfg: cfg,
	}
}

func TestPackageZip(t *testing.T) {
	testPackage(t, PackageZip)
}

func TestPackageTarGz(t *testing.T) {
	testPackage(t, PackageTarGz)
}

func TestPackageRPM(t *testing.T) {
	t.Skip("Flaky test")
	if err := HaveDocker(); err != nil {
		t.Skip("docker is required")
	}

	testPackage(t, PackageRPM)
}

func TestPackageDeb(t *testing.T) {
	t.Skip("Flaky test")
	if err := HaveDocker(); err != nil {
		t.Skip("docker is required")
	}

	testPackage(t, PackageDeb)
}

func testPackage(t testing.TB, pack func(PackageSpec) error) {
	spec := testPackageSpec(t).Evaluate()

	readme := spec.Files["README.txt"]
	readmePath := filepath.ToSlash(filepath.Clean(readme.Source))
	assert.True(t, strings.HasPrefix(readmePath, packageStagingDir))

	commit := spec.ExtraTags[0]
	expectedCommitHash := spec.cfg.Build.CommitHash()
	expected := "git-" + expectedCommitHash[:12]
	assert.Equal(t, expected, commit)

	if err := pack(spec); err != nil {
		t.Fatal(err)
	}
}

func TestRepoRoot(t *testing.T) {
	cfg, err := LoadSettings()
	require.NoError(t, err)

	assert.Equal(t, "github.com/elastic/elastic-agent", cfg.RepoInfo.RootImportPath)
	assert.True(t, filepath.IsAbs(cfg.RepoInfo.RootDir))
	cwd := filepath.Join(cfg.RepoInfo.RootDir, cfg.RepoInfo.SubDir)
	assert.Equal(t, CWD(), cwd)
}

func TestDumpVariables(t *testing.T) {
	cfg, err := LoadSettings()
	require.NoError(t, err)
	out, err := dumpVariables(cfg)
	require.NoError(t, err)
	t.Log(out)
}

func TestLoadSpecs(t *testing.T) {
	pkgs, err := LoadSpecs("../packaging/packages.yml")
	if err != nil {
		t.Fatal(err)
	}

	for flavor, s := range pkgs {
		out, err := yaml.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if testing.Verbose() {
			t.Log("Packaging flavor:", flavor, "\n", string(out))
		}
	}
}

// entryModes maps an archive entry name to the permissions of every entry
// written with that name.
type entryModes map[string][]os.FileMode

func readTarGzEntries(t *testing.T, path string) entryModes {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	gz, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gz.Close()

	entries := entryModes{}
	r := tar.NewReader(gz)
	for {
		h, err := r.Next()
		if errors.Is(err, io.EOF) {
			return entries
		}
		require.NoError(t, err)
		entries[h.Name] = append(entries[h.Name], h.FileInfo().Mode().Perm())
	}
}

func readZipEntries(t *testing.T, path string) entryModes {
	t.Helper()
	r, err := zip.OpenReader(path)
	require.NoError(t, err)
	defer r.Close()

	entries := entryModes{}
	for _, f := range r.File {
		entries[f.Name] = append(entries[f.Name], f.Mode().Perm())
	}
	return entries
}

// TestPackageNoDuplicateEntries checks that mappings overlapping on the same
// file produce a single archive entry, as extractors such as Gradle's tarTree
// or `tar --keep-old-files` reject duplicates. A directory mapping plus an
// explicit mapping of one of its files (like components/endpoint-security-resources.zip)
// must result in the explicit mapping.
func TestPackageNoDuplicateEntries(t *testing.T) {
	formats := []struct {
		name    string
		pack    func(PackageSpec) error
		ext     string
		entries func(*testing.T, string) entryModes
	}{
		{"tar.gz", PackageTarGz, ".tar.gz", readTarGzEntries},
		{"zip", PackageZip, ".zip", readZipEntries},
	}

	cases := []struct {
		name string
		// files builds the mappings given two directories, each holding a
		// "res.zip" and a file only present in that directory.
		files func(dirA, dirB string) map[string]PackageFile
		// want maps slash-separated archive entry names to their permissions.
		want map[string]os.FileMode
		// notOnWindows skips the case where the entry names are not portable.
		notOnWindows bool
	}{
		{
			name: "explicit file overrides directory mapping",
			files: func(dirA, _ string) map[string]PackageFile {
				return map[string]PackageFile{
					"components":         {Source: dirA + "/", Mode: 0o755},
					"components/res.zip": {Source: filepath.Join(dirA, "res.zip"), Mode: 0o644},
				}
			},
			want: map[string]os.FileMode{
				"tmp-pkg/components/res.zip": 0o644,
				"tmp-pkg/components/a-only":  0o755,
			},
		},
		{
			name: "directory source without trailing slash",
			files: func(dirA, _ string) map[string]PackageFile {
				return map[string]PackageFile{
					"components":         {Source: dirA, Mode: 0o755},
					"components/res.zip": {Source: filepath.Join(dirA, "res.zip"), Mode: 0o644},
				}
			},
			want: map[string]os.FileMode{
				"tmp-pkg/components/res.zip": 0o644,
				"tmp-pkg/components/a-only":  0o755,
			},
		},
		{
			name: "nested explicit file",
			files: func(dirA, _ string) map[string]PackageFile {
				return map[string]PackageFile{
					"components":            {Source: dirA + "/", Mode: 0o755},
					"components/sub/nested": {Source: filepath.Join(dirA, "sub", "nested"), Mode: 0o644},
				}
			},
			want: map[string]os.FileMode{
				"tmp-pkg/components/sub/nested": 0o644,
				"tmp-pkg/components/a-only":     0o755,
			},
		},
		{
			name: "explicit content mapping",
			files: func(dirA, _ string) map[string]PackageFile {
				return map[string]PackageFile{
					"components":         {Source: dirA + "/", Mode: 0o755},
					"components/res.zip": {Content: "generated", Mode: 0o644},
				}
			},
			want: map[string]os.FileMode{
				"tmp-pkg/components/res.zip": 0o644,
				"tmp-pkg/components/a-only":  0o755,
			},
		},
		{
			name: "missing explicit file keeps the directory entry",
			files: func(dirA, _ string) map[string]PackageFile {
				return map[string]PackageFile{
					"components": {Source: dirA + "/", Mode: 0o755},
					"components/res.zip": {
						Source:        filepath.Join(dirA, "missing.zip"),
						Mode:          0o644,
						SkipOnMissing: true,
					},
				}
			},
			want: map[string]os.FileMode{
				"tmp-pkg/components/res.zip": 0o755,
				"tmp-pkg/components/a-only":  0o755,
			},
		},
		{
			name: "overlapping directory mappings",
			files: func(dirA, dirB string) map[string]PackageFile {
				return map[string]PackageFile{
					"components":   {Source: dirA + "/", Mode: 0o755},
					"components/.": {Source: dirB + "/", Mode: 0o755},
				}
			},
			want: map[string]os.FileMode{
				"tmp-pkg/components/res.zip": 0o755,
				"tmp-pkg/components/a-only":  0o755,
				"tmp-pkg/components/b-only":  0o755,
			},
		},
		{
			name: "absolute targets",
			files: func(dirA, _ string) map[string]PackageFile {
				return map[string]PackageFile{
					"/var/lib/components":         {Source: dirA + "/", Mode: 0o755},
					"/var/lib/components/res.zip": {Source: filepath.Join(dirA, "res.zip"), Mode: 0o644},
				}
			},
			want: map[string]os.FileMode{
				"/var/lib/components/res.zip": 0o644,
				"/var/lib/components/a-only":  0o755,
			},
			notOnWindows: true,
		},
	}

	for _, format := range formats {
		for _, tc := range cases {
			t.Run(format.name+"/"+tc.name, func(t *testing.T) {
				if tc.notOnWindows && runtime.GOOS == "windows" {
					t.Skip("absolute unix paths are not absolute on Windows")
				}

				dirA, dirB := t.TempDir(), t.TempDir()
				for dir, names := range map[string][]string{
					dirA: {"res.zip", "a-only", filepath.Join("sub", "nested")},
					dirB: {"res.zip", "b-only"},
				} {
					for _, name := range names {
						path := filepath.Join(dir, name)
						require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
						require.NoError(t, os.WriteFile(path, []byte(name), 0o755))
					}
				}

				spec := testPackageSpec(t)
				spec.Files = tc.files(dirA, dirB)
				// Generated content files are staged in the package dir.
				spec.packageDir = t.TempDir()
				// The tmp- prefix skips the .sha512 file; the format adds the extension.
				spec.OutputFile = filepath.Join(t.TempDir(), "tmp-pkg")
				require.NoError(t, format.pack(spec.Evaluate()))

				got := format.entries(t, spec.OutputFile+format.ext)
				for name, modes := range got {
					require.Lenf(t, modes, 1, "entry %q written %d times", name, len(modes))
				}
				for name, mode := range tc.want {
					name = filepath.FromSlash(name)
					require.Equalf(t, []os.FileMode{mode}, got[name], "entry %q", name)
				}
			})
		}
	}
}
