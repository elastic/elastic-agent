// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package composed

import (
	"github.com/hashicorp/go-multierror"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Verifier is a verifier with a predefined set of verifiers.
// During each verify call it tries to call the first one and on failure fallbacks to
// the next one.
// Error is returned if all of them fail.
type Verifier struct {
	vv  []download.Verifier
	log *logger.Logger
}

func (v *Verifier) Name() string {
	return "composed.verifier"
}

// NewVerifier creates a verifier composed out of predefined set of verifiers.
// During each verify call it tries to call the first one and on failure fallbacks to
// the next one.
// Error is returned if all of them fail.
func NewVerifier(log *logger.Logger, verifiers ...download.Verifier) *Verifier {
	return &Verifier{
		log: log,
		vv:  verifiers,
	}
}

// Verify checks the package from configured source.
func (v *Verifier) Verify(a artifact.Artifact, version string, skipDefaultPgp bool, pgpBytes ...string) error {
	var err error

	for _, verifier := range v.vv {
		e := verifier.Verify(a, version, skipDefaultPgp, pgpBytes...)
		if e == nil {
			// Success
			return nil
		}

		err = multierror.Append(err, e)

		v.log.Warnw("Verifier failed!", "verifier", verifier.Name(), "error", e)
	}

	return err
}

func (v *Verifier) Reload(c *artifact.Config) error {
	for _, verifier := range v.vv {
		reloadable, ok := verifier.(download.Reloader)
		if !ok {
			continue
		}

		if err := reloadable.Reload(c); err != nil {
			return errors.New(err, "failed reloading artifact config for composed verifier")
		}
	}
	return nil
}
