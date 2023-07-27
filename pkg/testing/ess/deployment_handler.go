package ess

import (
	"context"
	"errors"
	"time"
)

// ErrDeploymentDoesNotExist is returned when the client has no deployment.
var ErrDeploymentDoesNotExist = errors.New("No Deployment for Client")

// DeplymentHandler wraps the clients that deal deploying and managing ES cloud instances
type DeplymentHandler interface {
	CreateDeployment(ctx context.Context, req CreateDeploymentRequest) (*CreateResponse, error)
	DeploymentIsReady(ctx context.Context, tick time.Duration) (bool, error)
	ShutdownDeployment(ctx context.Context) error
}

// CreateDeploymentRequest contains the needed config for a deployment create operation
type CreateDeploymentRequest struct {
	Name    string `json:"name"`
	Region  string `json:"region"`
	Version string `json:"version"`
}

// CreateResponse returns connection info from a create request
type CreateResponse struct {
	ID                    string
	ElasticsearchEndpoint string
	ESUser                string
	ESPassword            string
	KibanaEndpoint        string
	KibanaUsername        string
	KibanaPassword        string
}
