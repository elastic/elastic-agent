// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Config provides the configuration for running the runner.
type Config struct {
	AgentVersion      string
	AgentStackVersion string
	BuildDir          string
	GOVersion         string
	RepoDir           string
	ESS               *ESSConfig
	GCE               *GCEConfig

	// Matrix enables matrix testing. This explodes each test to
	// run on all supported platforms the runner supports.
	Matrix bool

	// SingleTest only has the runner run that specific test.
	SingleTest string

	// VerboseMode passed along a verbose mode flag to tests
	VerboseMode bool
}

// Validate returns an error if the information is invalid.
func (c *Config) Validate() error {
	if c.AgentVersion == "" {
		return errors.New("field AgentVersion must be set")
	}
	if c.AgentStackVersion == "" {
		return errors.New("field AgentStackVersion must be set")
	}
	if c.BuildDir == "" {
		return errors.New("field BuildDir must be set")
	}
	if c.GOVersion == "" {
		return errors.New("field GOVersion must be set")
	}
	if c.RepoDir == "" {
		return errors.New("field RepoDir must be set")
	}
	if c.ESS == nil {
		// in the future we could adjust to work on different providers
		// making this selectable (at the moment we just do ESS)
		return errors.New("config requires ESS to be set")
	}
	err := c.ESS.Validate()
	if err != nil {
		return fmt.Errorf("error validating ESS: %w", err)
	}
	if c.GCE == nil {
		// in the future we could adjust to work on different providers
		// making this selectable (at the moment we just do GCE)
		return errors.New("config requires GCE to be set")
	}
	err = c.GCE.Validate()
	if err != nil {
		return fmt.Errorf("error validating GCE: %w", err)
	}
	return err
}

// ESSType is a selector for the runner's underlying ESS instance
type ESSType string

// StatefulESS will start a traditional ESS deployment
var StatefulESS ESSType = "stateful"

// ServerlessESS will start a serverless ESS deployment
var ServerlessESS ESSType = "serverless"

// ESSConfig is the configuration for communicating with ESS.
type ESSConfig struct {
	APIKey         string
	Region         string
	DeploymentType ESSType
}

// Validate returns an error if the information is invalid.
func (ess *ESSConfig) Validate() error {
	if ess.APIKey == "" {
		return errors.New("field APIKey must be set")
	}
	if ess.Region == "" {
		return errors.New("field Region must be set")
	}
	return nil
}

// GCEConfig is the configuration for communicating with Google Compute Engine.
type GCEConfig struct {
	ServiceTokenPath string
	Datacenter       string

	content *serviceTokenContent
}

// Validate returns an error if the information is invalid.
func (gce *GCEConfig) Validate() error {
	if gce.ServiceTokenPath == "" {
		return errors.New("field ServiceTokenPath must be set")
	}
	if gce.Datacenter == "" {
		return errors.New("field Datacenter must be set")
	}
	return gce.ensureParsed()
}

// ProjectID returns the project ID from the service token.
func (gce *GCEConfig) ProjectID() (string, error) {
	err := gce.ensureParsed()
	if err != nil {
		return "", err
	}
	return gce.content.ProjectID, nil
}

// ClientEmail returns the client email from the service token.
func (gce *GCEConfig) ClientEmail() (string, error) {
	err := gce.ensureParsed()
	if err != nil {
		return "", err
	}
	return gce.content.ClientEmail, nil
}

func (gce *GCEConfig) ensureParsed() error {
	if gce.content != nil {
		// already parsed
		return nil
	}
	c, err := gce.parse()
	if err != nil {
		return err
	}
	gce.content = c
	return nil
}

func (gce *GCEConfig) parse() (*serviceTokenContent, error) {
	var content serviceTokenContent
	raw, err := os.ReadFile(gce.ServiceTokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read contents of %s: %w", gce.ServiceTokenPath, err)
	}
	err = json.Unmarshal(raw, &content)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON contents of %s: %w", gce.ServiceTokenPath, err)
	}
	if content.Type != "service_account" {
		return nil, fmt.Errorf("not a service account token at %s; type != service_account", gce.ServiceTokenPath)
	}
	return &content, nil
}

// serviceTokenContent is parsed content from a service token file.
type serviceTokenContent struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`

	// more fields exists but we only need the provided information
}
