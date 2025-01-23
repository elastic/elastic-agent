// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package filesource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"

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

type fileSourceConfig struct {
	Type string `config:"type"`
	Path string `config:"path"`
}

type contextProvider struct {
	logger *logger.Logger

	sources map[string]fileSourceConfig
}

// Run runs the filesource context provider.
func (c *contextProvider) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer watcher.Close()

	// invert the mapping to map paths to source names
	inverted := make(map[string][]string, len(c.sources))
	for sourceName, sourceCfg := range c.sources {
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
	paths := make([]string, 0, len(c.sources))
	for _, cfg := range c.sources {
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
	current := make(map[string]interface{}, len(c.sources))
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-watcher.Errors:
			if !ok {
				// watcher was closed
				return nil
			}
			c.logger.Errorf("file watcher errored: %s", err)
		case e, ok := <-watcher.Events:
			if !ok { // Channel was closed (i.e. Watcher.Close() was called).
				// watcher was closed
				return nil
			}

			path := filepath.Clean(e.Name)
			sources, ok := inverted[path]
			if !ok {
				// watching the directory, it can contain files that we are not watching
				// ignore these events unless we are actively watching this file
				continue
			}

			switch {
			case e.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove) != 0:
				// file was created, updated, or deleted (update the value)
				value := c.readContents(path)
				for _, source := range sources {
					current[source] = value
				}
				err = comm.Set(current)
				if err != nil {
					return fmt.Errorf("failed to set current context from notify event: %w", err)
				}
			}
		}
	}
}

func (c *contextProvider) readContents(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		c.logger.Errorf("failed to read file %q: %s", path, err)
		return ""
	}
	return string(data)
}

// ContextProviderBuilder builds the context provider.
func ContextProviderBuilder(log *logger.Logger, c *config.Config, _ bool) (corecomp.ContextProvider, error) {
	p := &contextProvider{
		logger: log,
	}
	if c != nil {
		err := c.UnpackTo(&p.sources)
		if err != nil {
			return nil, fmt.Errorf("failed to unpack config: %w", err)
		}
	}
	for sourceName, sourceCfg := range p.sources {
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
	}
	return p, nil
}
