// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package composed

import (
	"context"

	"github.com/hashicorp/go-multierror"
	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/version"
)

// Downloader is a downloader with a predefined set of downloaders.
// During each download call it tries to call the first one and on failure fallbacks to
// the next one.
// Error is returned if all of them fail.
type Downloader struct {
	dd []download.Downloader
}

// NewDownloader creates a downloader out of predefined set of downloaders.
// During each download call it tries to call the first one and on failure fallbacks to
// the next one.
// Error is returned if all of them fail.
func NewDownloader(downloaders ...download.Downloader) *Downloader {
	return &Downloader{
		dd: downloaders,
	}
}

// Download fetches the package from configured source.
// Returns absolute path to downloaded package and an error.
func (e *Downloader) Download(ctx context.Context, a artifact.Artifact, version *version.ParsedSemVer) (string, error) {
	var err error
	span, ctx := apm.StartSpan(ctx, "download", "app.internal")
	defer span.End()

	for _, d := range e.dd {
		s, e := d.Download(ctx, a, version)
		if e == nil {
			return s, nil
		}

		err = multierror.Append(err, e)
	}

	return "", err
}

func (e *Downloader) Reload(c *artifact.Config) error {
	for _, d := range e.dd {
		reloadable, ok := d.(download.Reloader)
		if !ok {
			continue
		}

		if err := reloadable.Reload(c); err != nil {
			return errors.New(err, "failed reloading artifact config for composed downloader")
		}
	}
	return nil
}
