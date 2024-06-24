// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	agtversion "github.com/elastic/elastic-agent/pkg/version"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	ascSuffix = ".asc"
)

// Verifier verifies a downloaded package by comparing with public ASC
// file from elastic.co website.
type Verifier struct {
	config     *artifact.Config
	client     http.Client
	defaultKey []byte
	log        *logger.Logger
}

func (v *Verifier) Name() string {
	return "http.verifier"
}

// NewVerifier create a verifier checking downloaded package on preconfigured
// location against a key stored on elastic.co website.
func NewVerifier(log *logger.Logger, config *artifact.Config, pgp []byte) (*Verifier, error) {
	if len(pgp) == 0 {
		return nil, errors.New("expecting PGP key received none", errors.TypeSecurity)
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

// Verify checks downloaded package on preconfigured
// location against a key stored on elastic.co website.
func (v *Verifier) Verify(a artifact.Artifact, version agtversion.ParsedSemVer, skipDefaultPgp bool, pgpBytes ...string) error {
	artifactPath, err := artifact.GetArtifactPath(a, version, v.config.OS(), v.config.Arch(), v.config.TargetDirectory)
	if err != nil {
		return errors.New(err, "retrieving package path")
	}

	if err = download.VerifySHA512HashWithCleanup(v.log, artifactPath); err != nil {
		return fmt.Errorf("failed to verify SHA512 hash: %w", err)
	}

	if err = v.verifyAsc(a, version, skipDefaultPgp, pgpBytes...); err != nil {
		var invalidSignatureErr *download.InvalidSignatureError
		if errors.As(err, &invalidSignatureErr) {
			if err := os.Remove(artifactPath); err != nil {
				v.log.Warnf("failed clean up after signature verification: failed to remove %q: %v",
					artifactPath, err)
			}
			if err := os.Remove(artifactPath + ascSuffix); err != nil {
				v.log.Warnf("failed clean up after sha512 check: failed to remove %q: %v",
					artifactPath+ascSuffix, err)
			}
		}
		return err
	}

	return nil
}

func (v *Verifier) verifyAsc(a artifact.Artifact, version agtversion.ParsedSemVer, skipDefaultKey bool, pgpSources ...string) error {
	filename, err := artifact.GetArtifactName(a, version, v.config.OS(), v.config.Arch())
	if err != nil {
		return errors.New(err, "retrieving package name")
	}

	fullPath, err := artifact.GetArtifactPath(a, version, v.config.OS(), v.config.Arch(), v.config.TargetDirectory)
	if err != nil {
		return errors.New(err, "retrieving package path")
	}

	ascURI, err := v.composeURI(filename, a.Artifact)
	if err != nil {
		return errors.New(err, "composing URI for fetching asc file", errors.TypeNetwork)
	}

	ascBytes, err := v.getPublicAsc(ascURI)
	if err != nil {
		return errors.New(err, fmt.Sprintf("fetching asc file from %s", ascURI), errors.TypeNetwork, errors.M(errors.MetaKeyURI, ascURI))
	}

	pgpBytes, err := download.FetchPGPKeys(
		v.log, v.client, v.defaultKey, skipDefaultKey, pgpSources)
	if err != nil {
		return fmt.Errorf("could not fetch pgp keys: %w", err)
	}

	return download.VerifyPGPSignatureWithKeys(v.log, fullPath, ascBytes, pgpBytes)
}

func (v *Verifier) composeURI(filename, artifactName string) (string, error) {
	upstream := v.config.SourceURI
	if !strings.HasPrefix(upstream, "http") && !strings.HasPrefix(upstream, "file") && !strings.HasPrefix(upstream, "/") {
		// always default to https
		upstream = fmt.Sprintf("https://%s", upstream)
	}

	// example: https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.1.1-x86_64.rpm
	uri, err := url.Parse(upstream)
	if err != nil {
		return "", errors.New(err, "invalid upstream URI", errors.TypeNetwork, errors.M(errors.MetaKeyURI, upstream))
	}

	uri.Path = path.Join(uri.Path, artifactName, filename+ascSuffix)
	return uri.String(), nil
}

func (v *Verifier) getPublicAsc(sourceURI string) ([]byte, error) {
	ctx, cancelFn := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFn()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURI, nil)
	if err != nil {
		return nil, errors.New(err, "failed create request for loading public key", errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, errors.New(err, "failed loading public key", errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("call to '%s' returned unsuccessful status code: %d", sourceURI, resp.StatusCode), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}

	return io.ReadAll(resp.Body)
}
