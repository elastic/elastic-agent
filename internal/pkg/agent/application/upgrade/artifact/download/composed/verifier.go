// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package composed

import (
	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
)

// Verifier is a verifier with a predefined set of verifiers.
// During each verify call it tries to call the first one and on failure fallbacks to
// the next one.
// Error is returned if all of them fail.
type Verifier struct {
	vv []download.Verifier
}

// NewVerifier creates a verifier composed out of predefined set of verifiers.
// During each verify call it tries to call the first one and on failure fallbacks to
// the next one.
// Error is returned if all of them fail.
func NewVerifier(verifiers ...download.Verifier) *Verifier {
	return &Verifier{
		vv: verifiers,
	}
}

// Verify checks the package from configured source.
func (e *Verifier) Verify(a artifact.Artifact, version string, skipDefaultPgp bool, pgpBytes ...string) error {
	var err error
	var checksumMismatchErr *download.ChecksumMismatchError
	var invalidSignatureErr *download.InvalidSignatureError

	for _, v := range e.vv {
		e := v.Verify(a, version, skipDefaultPgp, pgpBytes...)
		if e == nil {
			// Success
			return nil
		}

		err = multierror.Append(err, e)

		if errors.As(e, &checksumMismatchErr) || errors.As(err, &invalidSignatureErr) {
			// Stop verification chain on checksum/signature errors.
			break
		}
	}

	return err
}

func (e *Verifier) Reload(c *artifact.Config) error {
	for _, v := range e.vv {
		reloadable, ok := v.(download.Reloader)
		if !ok {
			continue
		}

		if err := reloadable.Reload(c); err != nil {
			return errors.New(err, "failed reloading artifact config for composed verifier")
		}
	}
	return nil
}
