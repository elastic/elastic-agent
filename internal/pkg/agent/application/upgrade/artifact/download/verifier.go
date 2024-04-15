// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package download

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/crypto/openpgp" //nolint:staticcheck // crypto/openpgp is only receiving security updates.

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

const (
	PgpSourceRawPrefix = "pgp_raw:"
	PgpSourceURIPrefix = "pgp_uri:"
)

var (
	ErrRemotePGPDownloadFailed = errors.New("Remote PGP download failed")
	ErrInvalidLocation         = errors.New("Remote PGP location is invalid")
	ErrUnknownPGPSource        = errors.New("unknown pgp source")
)

// warnLogger is a logger that only needs to implement Warnf.
type warnLogger interface {
	Warnf(format string, args ...interface{})
}

// loggerInfofWarnf is a logger that only needs to implement Infof and Warnf.
type infoWarnLogger interface {
	warnLogger

	Infof(format string, args ...interface{})
}

// ChecksumMismatchError indicates the expected checksum for a file does not
// match the computed checksum.
type ChecksumMismatchError struct {
	Expected string
	Computed string
	File     string
}

func (e *ChecksumMismatchError) Error() string {
	return "checksum mismatch for " + e.File + ": expected " + e.Expected + ", computed " + e.Computed
}

// InvalidSignatureError indicates the file's GPG signature is invalid.
type InvalidSignatureError struct {
	File string
	Err  error
}

func (e *InvalidSignatureError) Error() string {
	return "invalid signature for " + e.File + ": " + e.Err.Error()
}

// Unwrap returns the cause.
func (e *InvalidSignatureError) Unwrap() error { return e.Err }

// Verifier is an interface verifying the SHA512 checksum and PGP signature and
// of a downloaded artifact.
type Verifier interface {
	Name() string
	// Verify should verify the artifact, returning an error if any checks fail.
	// If the checksum does no match Verify returns a *download.ChecksumMismatchError.
	// If the PGP signature check fails then Verify returns a
	// *download.InvalidSignatureError.
	Verify(a artifact.Artifact, version agtversion.ParsedSemVer, skipDefaultPgp bool, pgpBytes ...string) error
}

// VerifySHA512HashWithCleanup calls VerifySHA512Hash and, in case of a
// *ChecksumMismatchError, performs a cleanup by deleting both the filename and
// filename.sha512 files. If the cleanup fails, it logs a warning.
func VerifySHA512HashWithCleanup(log infoWarnLogger, filename string) error {
	if err := VerifySHA512Hash(filename); err != nil {
		var checksumMismatchErr *ChecksumMismatchError
		if errors.As(err, &checksumMismatchErr) {
			if err := os.Remove(filename); err != nil {
				log.Warnf("failed clean up after sha512 verification: failed to remove %q: %v",
					filename, err)
			}
			if err := os.Remove(filename + ".sha512"); err != nil {
				log.Warnf("failed clean up after sha512 check: failed to remove %q: %v",
					filename+".sha512", err)
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			// it's not a simple hash mismatch, probably something is wrong with the hash file
			hashFileName := getHashFileName(filename)
			hashFileBytes, readErr := os.ReadFile(hashFileName)
			if readErr != nil {
				log.Warnf("error verifying the package using hash file %q, unable do read contents for logging: %v", getHashFileName(filename), readErr)
			} else {
				log.Warnf("error verifying the package using hash file %q, contents: %q", getHashFileName(filename), string(hashFileBytes))
			}
		}

		return err
	}

	return nil
}

func getHashFileName(filename string) string {
	const hashFileExt = ".sha512"
	if strings.HasSuffix(filename, hashFileExt) {
		return filename
	}
	return filename + hashFileExt
}

// VerifySHA512Hash checks that a sidecar file containing a sha512 checksum
// exists and that the checksum in the sidecar file matches the checksum of
// the file. It returns an error if validation fails.
func VerifySHA512Hash(filename string) error {
	hasher := sha512.New()
	checksumFileName := getHashFileName(filename)
	return VerifyChecksum(hasher, filename, checksumFileName)
}

// VerifyChecksum checks that the hash contained in checksumFileName correspond to the hash calculated for filename using
// hasher.Sum()
func VerifyChecksum(hasher hash.Hash, filename, checksumFileName string) error {
	// Read expected checksum.
	expectedHash, err := readChecksumFile(checksumFileName, filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("could not read checksum file: %w", err)
	}

	// Compute sha512 checksum.
	f, err := os.Open(filename)
	if err != nil {
		return errors.New(err, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, filename))
	}
	defer f.Close()

	if _, err := io.Copy(hasher, f); err != nil {
		return fmt.Errorf("faled to read file to calculate hash")
	}

	computedHash := hex.EncodeToString(hasher.Sum(nil))
	if computedHash != expectedHash {
		return &ChecksumMismatchError{
			Expected: expectedHash,
			Computed: computedHash,
			File:     filename,
		}
	}

	return nil
}

// readChecksumFile reads the checksum of the file named in filename from
// checksumFile. checksumFile is expected to contain the output from the
// shasum family of tools (e.g. sha512sum). If the checksum does not match then
// a *download.ChecksumMismatchError is returned.
func readChecksumFile(checksumFile, filename string) (string, error) {
	f, err := os.Open(checksumFile)
	if err != nil {
		return "", fmt.Errorf("failed to open checksum file %q: %w", checksumFile, err)
	}
	defer f.Close()

	// The format is a checksum, a space, a character indicating input mode ('*'
	// for binary, ' ' for text or where binary is insignificant), and name for
	// each FILE. See man sha512sum.
	//
	// {hash} SPACE (ASTERISK|SPACE) [{directory} SLASH] {filename}
	var checksum string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) != 2 {
			// Ignore malformed.
			continue
		}

		lineFilename := strings.TrimLeft(parts[1], "*")
		if lineFilename != filename {
			// Continue looking for a match.
			continue
		}

		checksum = parts[0]
	}

	if len(checksum) == 0 {
		return "", fmt.Errorf("checksum for %q was not found in %q", filename, checksumFile)
	}

	return checksum, nil
}

func VerifyPGPSignatureWithKeys(
	log infoWarnLogger, file string, asciiArmorSignature []byte, publicKeys [][]byte) error {
	var err error
	for i, key := range publicKeys {
		err = VerifyPGPSignature(file, asciiArmorSignature, key)
		if err == nil {
			log.Infof("Verification with PGP[%d] successful", i)
			return nil
		}
		log.Warnf("Verification with PGP[%d] failed: %v", i, err)
	}

	log.Warnf("Verification failed: %v", err)
	return fmt.Errorf("could not verify PGP signature of %q: %w", file, err)
}

// VerifyPGPSignature verifies the GPG signature of a file. It accepts the path
// to the file to verify, the ASCII armored signature, and the public key to
// check against. If there is a problem with the signature then a
// *download.InvalidSignatureError is returned.
func VerifyPGPSignature(file string, asciiArmorSignature, publicKey []byte) error {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicKey))
	if err != nil {
		return errors.New(err, "read armored key ring", errors.TypeSecurity)
	}

	f, err := os.Open(file)
	if err != nil {
		return errors.New(err, errors.TypeFilesystem, errors.M(errors.MetaKeyPath, file))
	}
	defer f.Close()

	_, err = openpgp.CheckArmoredDetachedSignature(keyring, f, bytes.NewReader(asciiArmorSignature))
	if err != nil {
		return &InvalidSignatureError{File: file, Err: err}
	}

	return nil
}

func FetchPGPKeys(log infoWarnLogger, client http.Client, defaultPGPKey []byte, skipDefaultPGP bool, pgpSources []string) ([][]byte, error) {
	var pgpKeys [][]byte
	if len(defaultPGPKey) > 0 && !skipDefaultPGP {
		pgpKeys = append(pgpKeys, defaultPGPKey)
		log.Infof("Default PGP appended")
	}

	for _, check := range pgpSources {
		if len(check) == 0 {
			continue
		}

		raw, err := PgpBytesFromSource(log, check, &client)
		if err != nil {
			return nil, err
		}

		if len(raw) == 0 {
			continue
		}

		pgpKeys = append(pgpKeys, raw)
	}

	if len(pgpKeys) == 0 {
		log.Infof("No PGP key available, skipping verification process")
		return nil, nil
	}

	log.Infof("Using %d PGP keys", len(pgpKeys))
	return pgpKeys, nil
}

func PgpBytesFromSource(log warnLogger, source string, client HTTPClient) ([]byte, error) {
	if strings.HasPrefix(source, PgpSourceRawPrefix) {
		return []byte(strings.TrimPrefix(source, PgpSourceRawPrefix)), nil
	}

	if strings.HasPrefix(source, PgpSourceURIPrefix) {
		pgpBytes, err := fetchPgpFromURI(strings.TrimPrefix(source, PgpSourceURIPrefix), client)
		if errors.Is(err, ErrRemotePGPDownloadFailed) || errors.Is(err, ErrInvalidLocation) {
			log.Warnf("Skipped remote PGP located at %q because it's unavailable: %v", strings.TrimPrefix(source, PgpSourceURIPrefix), err)
		} else if err != nil {
			log.Warnf("Failed to fetch remote PGP key from %q: %v",
				strings.TrimPrefix(source, PgpSourceURIPrefix), err)
		}

		return pgpBytes, nil
	}

	return nil, ErrUnknownPGPSource
}

func CheckValidDownloadUri(rawURI string) error {
	uri, err := url.Parse(rawURI)
	if err != nil {
		return err
	}

	if !strings.EqualFold(uri.Scheme, "https") {
		return multierror.Append(fmt.Errorf("failed to check URI %q: HTTPS is required", rawURI), ErrInvalidLocation)
	}

	return nil
}

func fetchPgpFromURI(uri string, client HTTPClient) ([]byte, error) {
	if err := CheckValidDownloadUri(uri); err != nil {
		return nil, err
	}

	ctx, cancelFn := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFn()
	// Change NewRequest to NewRequestWithContext and pass context it
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, multierror.Append(err, ErrRemotePGPDownloadFailed)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("call to '%s' returned unsuccessful status code: %d", uri, resp.StatusCode), errors.TypeNetwork, errors.M(errors.MetaKeyURI, uri))
	}

	return io.ReadAll(resp.Body)
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
