// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package filesource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/fsnotify/fsnotify"

	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func init() {
	// filesource provider reads and watches for changes on files that are defined in the provider configuration.
	//
	// To be notified when a file is change the provider will watch the parent directory of the file so if the file
	// is replaced that it will read the new contents. If a file doesn't exist or the provider is unable to read
	// the file then it will report the value as an empty string.
	//
	// If the provided path happens to be a directory then it just report the value as an empty string.
	composable.Providers.MustAddContextProvider("filesource", ContextProviderBuilder)
}

const (
	DefaultMaxSize = 4 * 1024 // 4KiB
)

type fileSourceConfig struct {
	Type string `config:"type"`
	Path string `config:"path"`
}

type providerConfig struct {
	Enabled bool                         `config:"enabled"` // handled by composable manager (but here to show that it is part of the config)
	Sources map[string]*fileSourceConfig `config:"sources"`
	MaxSize int                          `config:"max_size"`
}

type contextProvider struct {
	logger *logger.Logger

	cfg providerConfig
}

// Run runs the filesource context provider.
func (c *contextProvider) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer watcher.Close()

	// invert the mapping to map paths to source names
	inverted := make(map[string][]string, len(c.cfg.Sources))
	for sourceName, sourceCfg := range c.cfg.Sources {
		sources, ok := inverted[sourceCfg.Path]
		if !ok {
			sources = []string{sourceName}
		} else {
			sources = append(sources, sourceName)
		}
		inverted[sourceCfg.Path] = sources
	}

	// determine the paths to watch (watch is performed on the directories that contain the file)
	//
	// you cannot register the same directory multiple times so this ensures its only registered once
	paths := make([]string, 0, len(c.cfg.Sources))
	for _, cfg := range c.cfg.Sources {
		parent := filepath.Dir(cfg.Path)
		if !slices.Contains(paths, parent) {
			paths = append(paths, parent)
		}
	}
	for _, path := range paths {
		err = watcher.Add(path)
		if err != nil {
			return fmt.Errorf("failed to watch path %q: %w", path, err)
		}
	}

	// read the initial values after the watch has started
	// this ensures that if the value changed between this code and the loop below
	// the updated file changes will not be missed
	current := make(map[string]interface{}, len(c.cfg.Sources))
	readAll := func() error {
		for path, sources := range inverted {
			value := c.readContents(path)
			for _, source := range sources {
				current[source] = value
			}
		}
		err = comm.Set(current)
		if err != nil {
			return fmt.Errorf("failed to set current context: %w", err)
		}
		return nil
	}
	err = readAll()
	if err != nil {
		// context for the error already added
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-watcher.Errors:
			if ok {
				c.logger.Errorf("file watcher errored: %s", err)
				if errors.Is(err, fsnotify.ErrEventOverflow) {
					// the queue is full and some events have been dropped
					// at this point we don't know what has changed
					// clear the queue of events and read all again
					c.logger.Debug("draining file watcher queue")
					drainQueue(watcher.Events)
					c.logger.Infof("reading all sources to handle overflow")
					err = readAll()
					if err != nil {
						// context for the error already added
						c.logger.Error(err)
					}
				}
			}
		case e, ok := <-watcher.Events:
			if ok {
				path := filepath.Clean(e.Name)
				// Windows paths are case-insensitive
				if runtime.GOOS == "windows" {
					path = strings.ToLower(path)
				}
				sources, ok := inverted[path]
				if !ok {
					// watching the directory, it can contain files that we are not watching
					// ignore these events unless we are actively watching this file
					continue
				}

				switch {
				case e.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove) != 0:
					// file was created, updated, or deleted (update the value)
					changed := false
					value := c.readContents(path)
					for _, source := range sources {
						previous := current[source]
						if previous != value {
							current[source] = value
							changed = true
						}
					}
					if changed {
						err = comm.Set(current)
						if err != nil {
							return fmt.Errorf("failed to set current context from notify event: %w", err)
						}
					}
				}
			}
		}
	}
}

// readContents reads the contents of the file but places a cap on the size of the data that
// is allowed to be read. If the file is larger than the max size then it will only read up to
// the maximum size.
func (c *contextProvider) readContents(path string) string {
	maxSize := c.cfg.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}

	f, err := os.Open(path)
	if err != nil {
		c.logger.Errorf("failed to open file %q: %s", path, err)
	}
	defer f.Close()

	// determine the size needed in the buffer to read
	var size int
	if info, err := f.Stat(); err == nil {
		size64 := info.Size()
		if int64(int(size64)) == size64 {
			size = int(size64)
		}
	}
	size++ // one byte for final read at EOF

	// don't allow more than maxSize
	if size > maxSize {
		size = maxSize
	}

	// If a file claims a small size, read at least 512 bytes.
	// In particular, files in Linux's /proc claim size 0 but
	// then do not work right if read in small pieces,
	// so an initial read of 1 byte would not work correctly.
	if size < 512 {
		size = 512
	}

	data := make([]byte, 0, size)
	for {
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			if err != nil {
				c.logger.Errorf("failed to read file %q: %s", path, err)
				return ""
			}
			return string(data)
		}
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
	}
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(log *logger.Logger, c *config.Config, _ bool) (corecomp.ContextProvider, error) {
	p := &contextProvider{
		logger: log,
	}
	if c != nil {
		err := c.UnpackTo(&p.cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack config: %w", err)
		}
	}
	for sourceName, sourceCfg := range p.cfg.Sources {
		if sourceCfg.Type != "" && sourceCfg.Type != "raw" {
			return nil, fmt.Errorf("%q defined an unsupported type %q", sourceName, sourceCfg.Type)
		}
		if sourceCfg.Path == "" {
			return nil, fmt.Errorf("%q is missing a defined path", sourceName)
		}
		// only use an absolute path (convert from relative)
		if !filepath.IsAbs(sourceCfg.Path) {
			path, err := filepath.Abs(sourceCfg.Path)
			if err != nil {
				return nil, fmt.Errorf("%q failed to determine absolute path for %q: %w", sourceName, sourceCfg.Path, err)
			}
			sourceCfg.Path = path
		}
		path := filepath.Dir(sourceCfg.Path)
		if path == "" || path == "." {
			return nil, fmt.Errorf("%q has a path %q that is invalid", sourceName, sourceCfg.Path)
		}
		// Windows paths are case-insensitive, force lower here to simplify the implementation
		if runtime.GOOS == "windows" {
			sourceCfg.Path = strings.ToLower(sourceCfg.Path)
		}
		p.cfg.Sources[sourceName] = sourceCfg
	}
	return p, nil
}

func drainQueue(e <-chan fsnotify.Event) {
	for {
		select {
		case _, ok := <-e:
			if !ok {
				return
			}
		default:
			return
		}
	}
}
