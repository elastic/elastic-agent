// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package http

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"

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
	config        *artifact.Config
	client        http.Client
	pgpBytes      []byte
	allowEmptyPgp bool
	log           *logger.Logger
}

func (v *Verifier) Name() string {
	return "http.verifier"
}

// NewVerifier create a verifier checking downloaded package on preconfigured
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
func (v *Verifier) Verify(a artifact.Artifact, version string, skipDefaultPgp bool, pgpBytes ...string) error {
	fullPath, err := artifact.GetArtifactPath(a, version, v.config.OS(), v.config.Arch(), v.config.TargetDirectory)
	if err != nil {
		return errors.New(err, "retrieving package path")
	}

	if err = download.VerifySHA512Hash(fullPath); err != nil {
		var checksumMismatchErr *download.ChecksumMismatchError
		if errors.As(err, &checksumMismatchErr) {
			os.Remove(fullPath)
			os.Remove(fullPath + ".sha512")
		}
		return err
	}

	if err = v.verifyAsc(a, version, skipDefaultPgp, pgpBytes...); err != nil {
		var invalidSignatureErr *download.InvalidSignatureError
		if errors.As(err, &invalidSignatureErr) {
			os.Remove(fullPath + ".asc")
		}
		return err
	}

	return nil
}

func (v *Verifier) verifyAsc(a artifact.Artifact, version string, skipDefaultPgp bool, pgpSources ...string) error {
	var pgpBytes [][]byte
	if len(v.pgpBytes) > 0 && !skipDefaultPgp {
		v.log.Infof("Default PGP being appended")
		pgpBytes = append(pgpBytes, v.pgpBytes)
	}

	for _, check := range pgpSources {
		if len(check) == 0 {
			continue
		}
		raw, err := download.PgpBytesFromSource(v.log, check, &v.client)
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
	if err != nil && v.allowEmptyPgp {
		// asc not available but we allow empty for dev use-case
		return nil
	} else if err != nil {
		return errors.New(err, fmt.Sprintf("fetching asc file from %s", ascURI), errors.TypeNetwork, errors.M(errors.MetaKeyURI, ascURI))
	}

	for i, check := range pgpBytes {
		err = download.VerifyGPGSignature(fullPath, ascBytes, check)
		if err == nil {
			// verify successful
			v.log.Infof("Verification with PGP[%d] successful", i)
			return nil
		}
		v.log.Warnf("Verification with PGP[%d] failed: %v", i, err)
	}

	v.log.Warnf("Verification failed")

	// return last error
	return err
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
	// Change NewRequest to NewRequestWithContext and pass context it
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURI, nil)
	if err != nil {
		return nil, errors.New(err, "failed create request for loading public key", errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.New(err, "failed loading public key", errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("call to '%s' returned unsuccessful status code: %d", sourceURI, resp.StatusCode), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}

	return ioutil.ReadAll(resp.Body)
}
