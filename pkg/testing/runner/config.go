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
}

// Validate returns an error if the information is invalid.
func (c *Config) Validate() error {
	if c.AgentVersion == "" {
		return errors.New("AgentVersion must be set")
	}
	if c.AgentStackVersion == "" {
		return errors.New("AgentStackVersion must be set")
	}
	if c.BuildDir == "" {
		return errors.New("BuildDir must be set")
	}
	if c.GOVersion == "" {
		return errors.New("GOVersion must be set")
	}
	if c.RepoDir == "" {
		return errors.New("RepoDir must be set")
	}
	if c.ESS == nil {
		// in the future we could adjust to work on different providers
		// making this selectable (at the moment we just do ESS)
		return errors.New("config requires ESS to be set")
	}
	err := c.ESS.Validate()
	if err != nil {
		return fmt.Errorf("ESS error: %w", err)
	}
	if c.GCE == nil {
		// in the future we could adjust to work on different providers
		// making this selectable (at the moment we just do GCE)
		return errors.New("config requires GCE to be set")
	}
	err = c.GCE.Validate()
	if err != nil {
		return fmt.Errorf("GCE error: %w", err)
	}
	return err
}

// ESSConfig is the configuration for communicating with ESS.
type ESSConfig struct {
	APIKey string
	Region string
}

// Validate returns an error if the information is invalid.
func (ess *ESSConfig) Validate() error {
	if ess.APIKey == "" {
		return errors.New("APIKey must be set")
	}
	if ess.Region == "" {
		return errors.New("Region must be set")
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
		return errors.New("ServiceTokenPath must be set")
	}
	if gce.Datacenter == "" {
		return errors.New("Datacenter must be set")
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
