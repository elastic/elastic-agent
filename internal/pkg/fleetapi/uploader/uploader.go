// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package uploader contains the methods needed to upload a file using fleet-server's upload endpoints.
package uploader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
)

// The following constants correspond with fleer-server API paths for file uploads.
const (
	PathNewUpload    = "/api/fleet/uploads"
	PathChunk        = "/api/fleet/uploads/%s/%d"
	PathFinishUpload = "/api/fleet/uploads/%s"
)

// FileData contains metadata about a file.
type FileData struct {
	Size        int64  `json:"size"`
	Name        string `json:"name"`
	Extension   string `json:"ext"`
	Mime        string `json:"mime_type"`
	Compression string `json:"Compression"`
	Hash        struct {
		SHA256 string `json:"sha256"`
		MD5    string `json:"md5"`
	} `json:"hash"`
	Accessed    string   `json:"accessed"`
	Attributes  []string `json:"attributes"`
	Created     string   `json:"created"`
	CTime       string   `json:"ctime"`
	Device      string   `json:"device"`
	Directory   string   `json:"directory"`
	DriveLetter string   `json:"drive_letter"`
	Ext         string   `json:"extension"`
	GID         string   `json:"gid"`
	Group       string   `json:"group"`
	INode       string   `json:"inode"`
	Mode        string   `json:"mode"`
	MTime       string   `json:"mtime"`
	Owner       string   `json:"owner"`
	Path        string   `json:"path"`
	TargetPath  string   `json:"target_path"`
	Type        string   `json:"type"`
	UID         string   `json:"uid"`
}

// NewUploadRequest is the struct that is passed as the request body when starting a new file upload.
type NewUploadRequest struct {
	AgentID  string     `json:"agent_id"`
	ActionID string     `json:"action_id"`
	Source   string     `json:"source"`
	File     FileData   `json:"file"`
	Contents []FileData `json:"contents"`
	Event    struct {
		ID string `json:"id"`
	} `json:"event"`
	Host struct {
		Hostname string `json:"hostname"`
	} `json:"host"`
}

// NewUploadResponse is the body for the success case when requesting a new file upload.
type NewUploadResponse struct {
	UploadID  string `json:"upload_id"`
	ChunkSize int64  `json:"chunk_size"`
}

// retrySender wraps the underlying Sender with retry logic.
type retrySender struct {
	c    client.Sender
	max  int
	wait backoff.Backoff
}

// Send calls the underlying Sender's Send method. If a 429 status code is returned the request is retried after a backoff period.
// TODO What to do if another error or status is received?
func (r *retrySender) Send(ctx context.Context, method, path string, params url.Values, headers http.Header, body io.Reader) (resp *http.Response, err error) {
	r.wait.Reset()

	var b bytes.Buffer
	tr := io.TeeReader(body, &b)
	for i := 0; i < r.max; i++ {
		resp, err = r.c.Send(ctx, method, path, params, headers, tr)
		if err != nil {
			return resp, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			tr = bytes.NewReader(b.Bytes())
			r.wait.Wait()
			continue
		}
		return resp, err
	}
	return resp, err
}

// URI calls the underlying Sender's URI method.
func (r *retrySender) URI() string {
	return r.c.URI()
}

// Client provides methods to upload a file to ES through fleet-server.
type Client struct {
	agentID string
	c       client.Sender
}

// New returns a new Client for the agent identified by the passed id.
// The sender is wrapped with retry logic specified by the Uploader config.
// Any request that would return a 429 (too many requests) is retried (up to maxRetries times) with a backoff.
func New(id string, c client.Sender, cfg config.Uploader) *Client {
	return &Client{
		agentID: id,
		c: &retrySender{
			c:    c,
			max:  cfg.MaxRetries,
			wait: backoff.NewEqualJitterBackoff(nil, cfg.InitDur, cfg.MaxDur),
		},
	}
}

// New sends a new file upload request to the fleet-server.
func (c *Client) New(ctx context.Context, r *NewUploadRequest) (*NewUploadResponse, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	resp, err := c.c.Send(ctx, "POST", PathNewUpload, nil, nil, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, client.ExtractError(resp.Body)
	}

	var newUploadResp NewUploadResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&newUploadResp); err != nil {
		return nil, err
	}
	return &newUploadResp, nil
}

// Chunk uploads a file chunk to fleet-server.
func (c *Client) Chunk(ctx context.Context, uploadID string, chunkID int, r io.Reader) error {
	resp, err := c.c.Send(ctx, "PUT", fmt.Sprintf(PathChunk, uploadID, chunkID), nil, nil, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return client.ExtractError(resp.Body)
	}
	return nil
}

// Finish calls the finalize endpoint for the file upload.
func (c *Client) Finish(ctx context.Context, id string) error {
	resp, err := c.c.Send(ctx, "POST", fmt.Sprintf(PathFinishUpload, id), nil, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return client.ExtractError(resp.Body)
	}
	return nil
}

// UploadDiagnostics is a wrapper to upload a diagnostics request identified by the passed action id contained in the buffer to fleet-server.
func (c *Client) UploadDiagnostics(ctx context.Context, id string, b *bytes.Buffer) error {
	size := b.Len()
	upReq := NewUploadRequest{
		AgentID:  c.agentID,
		ActionID: id,
		File: FileData{
			Size:        int64(size),
			Name:        fmt.Sprintf("elastic-agent-diagnostics-%s-%s.zip", c.agentID, id),
			Extension:   "zip",
			Mime:        "application/zip",
			Compression: "Deflate",
			Hash: struct {
				SHA256 string `json:"sha256"`
				MD5    string `json:"md5"`
			}{
				SHA256: fmt.Sprintf("%x", sha256.Sum256(b.Bytes())),
			},
			Created: time.Now().UTC().Format(time.RFC3339),
		},
	}
	upResp, err := c.New(ctx, &upReq)
	if err != nil {
		return err
	}

	uploadID := upResp.UploadID
	chunkSize := upResp.ChunkSize
	totalChunks := int(math.Ceil(float64(size) / float64(chunkSize)))
	for chunk := 0; chunk < totalChunks; chunk++ {
		err := c.Chunk(ctx, uploadID, chunk, io.LimitReader(b, chunkSize))
		if err != nil {
			return err
		}
	}

	return c.Finish(ctx, uploadID)
}
