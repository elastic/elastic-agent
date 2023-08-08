// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fs

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	ascSuffix = ".asc"
)

// Verifier verifies an artifact's GPG signature as read from the filesystem.
// The signature is validated against Elastic's public GPG key that is
// embedded into Elastic Agent.
type Verifier struct {
	config        *artifact.Config
	client        http.Client
	pgpBytes      []byte
	allowEmptyPgp bool
	log           *logger.Logger
}

// NewVerifier creates a verifier checking downloaded package on preconfigured
// location against a key stored on elastic.co website.
func NewVerifier(log *logger.Logger, config *artifact.Config, allowEmptyPgp bool, pgp []byte) (*Verifier, error) {
	if len(pgp) == 0 && !allowEmptyPgp {
		return nil, errors.New("expecting PGP but retrieved none", errors.TypeSecurity)
	}

	client, err := config.HTTPTransportSettings.Client(
		httpcommon.WithAPMHTTPInstrumentation(),
		httpcommon.WithModRoundtripper(func(rt http.RoundTripper) http.RoundTripper {
			return download.WithHeaders(rt, download.Headers)
		}),
	)
	if err != nil {
		return nil, err
	}

	v := &Verifier{
		config:        config,
		client:        *client,
		allowEmptyPgp: allowEmptyPgp,
		pgpBytes:      pgp,
		log:           log,
	}

	return v, nil
}

// Verify checks downloaded package on preconfigured
// location against a key stored on elastic.co website.
func (v *Verifier) Verify(a artifact.Artifact, version string, skipDefaultPgp bool, pgpBytes ...string) error {
	filename, err := artifact.GetArtifactName(a, version, v.config.OS(), v.config.Arch())
	if err != nil {
		return errors.New(err, "retrieving package name")
	}

	fullPath := filepath.Join(v.config.TargetDirectory, filename)

	if err = download.VerifySHA512Hash(fullPath); err != nil {
		var checksumMismatchErr *download.ChecksumMismatchError
		if errors.As(err, &checksumMismatchErr) {
			os.Remove(fullPath)
			os.Remove(fullPath + ".sha512")
		}
		return err
	}

	if err = v.verifyAsc(fullPath, skipDefaultPgp, pgpBytes...); err != nil {
		var invalidSignatureErr *download.InvalidSignatureError
		if errors.As(err, &invalidSignatureErr) {
			os.Remove(fullPath + ".asc")
		}
		return err
	}

	return nil
}

func (v *Verifier) Reload(c *artifact.Config) error {
	// reload client
	client, err := c.HTTPTransportSettings.Client(
		httpcommon.WithAPMHTTPInstrumentation(),
		httpcommon.WithModRoundtripper(func(rt http.RoundTripper) http.RoundTripper {
			return download.WithHeaders(rt, download.Headers)
		}),
	)
	if err != nil {
		return errors.New(err, "http.verifier: failed to generate client out of config")
	}

	v.client = *client
	v.config = c

	return nil
}

func (v *Verifier) verifyAsc(fullPath string, skipDefaultPgp bool, pgpSources ...string) error {
	var pgpBytes [][]byte
	if len(v.pgpBytes) > 0 && !skipDefaultPgp {
		v.log.Infof("Default PGP being appended")
		pgpBytes = append(pgpBytes, v.pgpBytes)
	}

	for _, check := range pgpSources {
		if len(check) == 0 {
			continue
		}
		raw, err := download.PgpBytesFromSource(check, v.client)
		if err != nil {
			return err
		}
		if len(raw) == 0 {
			continue
		}

		pgpBytes = append(pgpBytes, raw)
	}

	if len(pgpBytes) == 0 {
		// no pgp available skip verification process
		v.log.Infof("No checks defined")
		return nil
	}
	v.log.Infof("Using %d PGP keys", len(pgpBytes))

	ascBytes, err := v.getPublicAsc(fullPath)
	if err != nil && v.allowEmptyPgp {
		// asc not available but we allow empty for dev use-case
		return nil
	} else if err != nil {
		return err
	}

	for i, check := range pgpBytes {
		err = download.VerifyGPGSignature(fullPath, ascBytes, check)
		if err == nil {
			// verify successful
			v.log.Infof("Verification with PGP[%d] successful", i)
			return nil
		}
		v.log.Warnf("Verification with PGP[%d] succfailed: %v", i, err)
	}

	v.log.Warnf("Verification failed")

	// return last error
	return err
}

func (v *Verifier) getPublicAsc(fullPath string) ([]byte, error) {
	fullPath = fmt.Sprintf("%s%s", fullPath, ascSuffix)
	b, err := ioutil.ReadFile(fullPath)
	if err != nil {
		return nil, errors.New(err, fmt.Sprintf("fetching asc file from '%s'", fullPath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fullPath))
	}

	return b, nil
}
