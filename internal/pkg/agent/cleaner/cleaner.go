// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cleaner

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/fileutil"
)

// Wait interval.
// If the watchFile was not modified after this interval, then remove all the files in the removeFiles array
const defaultCleanWait = 15 * time.Minute

type Cleaner struct {
	log         *logp.Logger
	watchFile   string
	removeFiles []string
	cleanWait   time.Duration

	mx sync.Mutex
}

type OptionFunc func(c *Cleaner)

func New(log *logp.Logger, watchFile string, removeFiles []string, opts ...OptionFunc) *Cleaner {
	c := &Cleaner{
		log:         log,
		watchFile:   watchFile,
		removeFiles: removeFiles,
		cleanWait:   defaultCleanWait,
	}

	for _, opt := range opts {
		opt(c)
	}
	return c
}

func WithCleanWait(cleanWait time.Duration) OptionFunc {
	return func(c *Cleaner) {
		c.cleanWait = cleanWait
	}
}

func (c *Cleaner) Run(ctx context.Context) error {
	wait, done, err := c.process()
	if err != nil {
		return err
	}

	if done {
		return nil
	}

	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			c.log.Debug("cleaner: timer triggered")
			wait, done, err = c.process()
			if err != nil {
				return err
			}

			if done {
				return nil
			}
			t.Reset(wait)
		}
	}
}

func (c *Cleaner) process() (wait time.Duration, done bool, err error) {
	modTime, err := fileutil.GetModTime(c.watchFile)
	if err != nil {
		return
	}

	c.log.Debugf("cleaner: check file %s mod time: %v", c.watchFile, modTime)
	curDur := time.Since(modTime)
	if curDur > c.cleanWait {
		c.log.Debugf("cleaner: file %s modification expired", c.watchFile)
		c.deleteFiles()
		return wait, true, nil
	}
	wait = c.cleanWait - curDur
	return wait, false, nil
}

func (c *Cleaner) deleteFiles() {
	c.log.Debugf("cleaner: delete files: %v", c.removeFiles)
	c.mx.Lock()
	defer c.mx.Unlock()
	for _, fp := range c.removeFiles {
		c.log.Debugf("cleaner: delete file: %v", fp)
		err := os.Remove(fp)
		if err != nil {
			c.log.Warnf("cleaner: delete file %v failed: %v", fp, err)
		}
	}
}
