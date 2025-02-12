// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package helm

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/downloader"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/repo"
)

func ensureRepository(repoName, repoURL string, settings *cli.EnvSettings) error {
	repoFile := settings.RepositoryConfig
	// Load existing repositories
	file, err := repo.LoadFile(repoFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			file = repo.NewFile()
		} else {
			return fmt.Errorf("could not load Helm repository config: %w", err)
		}
	}

	// Check if the repository is already added
	for _, entry := range file.Repositories {
		if entry.URL == repoURL {
			// repository already exists
			return nil
		}
	}

	// Add the repository
	entry := &repo.Entry{
		Name: repoName,
		URL:  repoURL,
	}

	chartRepo, err := repo.NewChartRepository(entry, getter.All(settings))
	if err != nil {
		return fmt.Errorf("could not create repo %s: %w", repoURL, err)
	}

	_, err = chartRepo.DownloadIndexFile()
	if err != nil {
		return fmt.Errorf("could not download index file for repo %s: %w", repoURL, err)
	}

	file.Update(entry)
	if err := file.WriteFile(repoFile, 0o644); err != nil {
		return fmt.Errorf("could not write Helm repository config: %w", err)
	}

	return nil
}

func BuildChartDependencies(chartPath string) error {
	settings := cli.New()
	settings.SetNamespace("")
	actionConfig := &action.Configuration{}

	chartFile, err := os.ReadFile(fmt.Sprintf("%s/Chart.yaml", chartPath))
	if err != nil {
		return fmt.Errorf("could not read %s/Chart.yaml: %w", chartPath, err)
	}

	dependencies := struct {
		Entry []struct {
			Name       string `yaml:"name"`
			Repository string `yaml:"repository"`
		} `yaml:"dependencies"`
	}{}

	err = yaml.Unmarshal(chartFile, &dependencies)
	if err != nil {
		return fmt.Errorf("could not unmarshal %s/Chart.yaml: %w", chartPath, err)
	}

	for _, dep := range dependencies.Entry {
		err := ensureRepository(dep.Name, dep.Repository, settings)
		if err != nil {
			return err
		}
	}

	err = actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "",
		func(format string, v ...interface{}) {})
	if err != nil {
		return fmt.Errorf("failed to init helm action config: %w", err)
	}

	client := action.NewDependency()

	registryClient, err := registry.NewClient(
		registry.ClientOptDebug(settings.Debug),
		registry.ClientOptEnableCache(true),
		registry.ClientOptWriter(os.Stderr),
		registry.ClientOptCredentialsFile(settings.RegistryConfig),
	)
	if err != nil {
		return fmt.Errorf("failed to create helm registry client: %w", err)
	}

	buffer := bytes.Buffer{}

	man := &downloader.Manager{
		Out:              bufio.NewWriter(&buffer),
		ChartPath:        chartPath,
		Keyring:          client.Keyring,
		SkipUpdate:       true,
		Getters:          getter.All(settings),
		RegistryClient:   registryClient,
		RepositoryConfig: settings.RepositoryConfig,
		RepositoryCache:  settings.RepositoryCache,
		Debug:            settings.Debug,
	}
	if client.Verify {
		man.Verify = downloader.VerifyIfPossible
	}
	err = man.Build()
	if err != nil {
		return fmt.Errorf("failed to build helm dependencies: %w", err)
	}
	return nil
}
