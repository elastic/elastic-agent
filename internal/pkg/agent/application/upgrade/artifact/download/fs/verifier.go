// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fs

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

const (
	ascSuffix = ".asc"
)

// Verifier verifies an artifact's GPG signature as read from the filesystem.
// The signature is validated against Elastic's public GPG key that is
// embedded into Elastic Agent.
type Verifier struct {
	config     *artifact.Config
	client     http.Client
	defaultKey []byte
	log        *logger.Logger
}

func (v *Verifier) Name() string {
	return "fs.verifier"
}

// NewVerifier creates a verifier checking downloaded package on preconfigured
// location against a key stored on elastic.co website.
func NewVerifier(log *logger.Logger, config *artifact.Config, pgp []byte) (*Verifier, error) {
	if len(pgp) == 0 {
		return nil, errors.New("expecting PGP key but received none", errors.TypeSecurity)
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
		config:     config,
		client:     *client,
		defaultKey: pgp,
		log:        log,
	}

	return v, nil
}

// Verify checks downloaded package on preconfigured
// location against a key stored on elastic.co website.
func (v *Verifier) Verify(a artifact.Artifact, version agtversion.ParsedSemVer, skipDefaultPgp bool, pgpBytes ...string) error {
	filename, err := artifact.GetArtifactName(a, version, v.config.OS(), v.config.Arch())
	if err != nil {
		return fmt.Errorf("could not get artifact name: %w", err)
	}

	artifactPath := filepath.Join(v.config.TargetDirectory, filename)

	if err = download.VerifySHA512HashWithCleanup(v.log, artifactPath); err != nil {
		return fmt.Errorf("failed to verify SHA512 hash: %w", err)
	}

	if err = v.verifyAsc(artifactPath, skipDefaultPgp, pgpBytes...); err != nil {
		var invalidSignatureErr *download.InvalidSignatureError
		if errors.As(err, &invalidSignatureErr) {
			if err := os.Remove(artifactPath + ".asc"); err != nil {
				v.log.Warnf("failed clean up after signature verification: failed to remove %q: %v",
					artifactPath+".asc", err)
			}
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

func (v *Verifier) verifyAsc(fullPath string, skipDefaultKey bool, pgpSources ...string) error {
	var pgpBytes [][]byte
	pgpBytes, err := download.FetchPGPKeys(
		v.log, v.client, v.defaultKey, skipDefaultKey, pgpSources)
	if err != nil {
		return fmt.Errorf("could not fetch pgp keys: %w", err)
	}

	ascBytes, err := v.getPublicAsc(fullPath)
	if err != nil {
		return fmt.Errorf("could not get .asc file: %w", err)
	}

	return download.VerifyPGPSignatureWithKeys(v.log, fullPath, ascBytes, pgpBytes)
}

func (v *Verifier) getPublicAsc(fullPath string) ([]byte, error) {
	fullPath = fmt.Sprintf("%s%s", fullPath, ascSuffix)
	b, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, errors.New(err, fmt.Sprintf("fetching asc file from '%s'", fullPath), errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fullPath))
	}

	return b, nil
}
