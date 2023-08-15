// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ogc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Config is the configuration for using OGC.
type Config struct {
	ServiceTokenPath string
	Datacenter       string

	content *serviceTokenContent
}

// Validate returns an error if the information is invalid.
func (c *Config) Validate() error {
	if c.ServiceTokenPath == "" {
		return errors.New("field ServiceTokenPath must be set")
	}
	if c.Datacenter == "" {
		return errors.New("field Datacenter must be set")
	}
	return c.ensureParsed()
}

// ProjectID returns the project ID from the service token.
func (c *Config) ProjectID() (string, error) {
	err := c.ensureParsed()
	if err != nil {
		return "", err
	}
	return c.content.ProjectID, nil
}

// ClientEmail returns the client email from the service token.
func (c *Config) ClientEmail() (string, error) {
	err := c.ensureParsed()
	if err != nil {
		return "", err
	}
	return c.content.ClientEmail, nil
}

func (c *Config) ensureParsed() error {
	if c.content != nil {
		// already parsed
		return nil
	}
	content, err := c.parse()
	if err != nil {
		return err
	}
	c.content = content
	return nil
}

func (c *Config) parse() (*serviceTokenContent, error) {
	var content serviceTokenContent
	raw, err := os.ReadFile(c.ServiceTokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read contents of %s: %w", c.ServiceTokenPath, err)
	}
	err = json.Unmarshal(raw, &content)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON contents of %s: %w", c.ServiceTokenPath, err)
	}
	if content.Type != "service_account" {
		return nil, fmt.Errorf("not a service account token at %s; type != service_account", c.ServiceTokenPath)
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
