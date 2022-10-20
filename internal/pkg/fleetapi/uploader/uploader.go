// Package uploader contains the methods needed to upload a file using fleet-server's upload endpoints.
package uploader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
)

const (
	NewUploadPath    = "/api/fleet/uploads"
	ChunkPath        = "/api/fleet/uploads/%s/%d"
	FinishUploadPath = "/api/fleet/uploads/%s"
)

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
		Hostname string `json::hostname`
	} `json:"host"`
}

type NewUploadResponse struct {
	UploadID  string `json:"upload_id"`
	ChunkSize int64  `json:"chunck_size"`
}

type Client struct {
	c       *client.Sender
	agentID string
}

func New(c *client.Client, id string) *Client {
	return &client{
		c:       c,
		agentID: id,
	}
}

// New completes a new file upload request to the fleet-server.
func (c *client) New(ctx context.Context, r *NewUploadRequest) (*NewUploadResponse, error) {
	b, err := json.Marshall(r)
	if err != nil {
		return nil, err
	}
	resp, err := c.c.Send(ctx, "POST", NewUploadPath, nil, nil, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, client.ExtractBody(resp.Body)
	}

	var newUploadResp NewUploadResponse
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&newUploadResp); err != nil {
		return nil, err
	}
	return newUploadResp, nil
}

// Chunk uploads a new chunk to fleet-server.
func (c *client) Chunk(ctx context.Context, uploadID string, chunkID int, r io.Reader) error {
	resp, err := c.c.Send(ctx, "PUT", fmt.Sprintf(ChunkPath, uploadID, chunkID), nil, nil, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return client.ExtractError(resp.Body)
	}
	return nil
}

// Finish calls the finalize endpoint for the passed upload ID.
func (c *client) Finish(ctx context.Context, id string) error {
	resp, err := c.c.Send(ctx, "POST", fmt.Sprintf(FinishUploadPath, id), nil, nil, nil)
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
// TODO retries for 429 responses
// TODO What to do if another error is recieved?
func (c *client) UploadDiagnostics(ctx context.Context, id string, b *bytes.Buffer) error {
	size := b.Len()
	upReq := NewUploadRequest{
		Size:        int64(size),
		Name:        fmt.Sprintf("elastic-agent-diagnostics-%s-%s.zip", c.agentID, id),
		Extension:   "zip",
		Mime:        "application/zip",
		Compression: "Deflate",
		Hash: struct {
			SHA256 string
		}{
			SHA256: fmt.Sprintf("%x", sha256.Sum(b.Bytes())),
		},
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	upResp, err := c.New(ctx, &upReq)
	if err != nil {
		return err
	}

	uploadID := upResp.UploadID
	chunckSize := upResp.ChunckSize
	totalChunks := math.Ceil(float64(size) / float64(chunkSize))
	for chunk := 0; chunk < totalChunks; chunk++ {
		err := c.Chunk(ctx, uploadID, chunk, &io.LimitedReader{b, chunkSize})
		if err != nil {
			return err
		}
	}

	return c.Finish(ctx, uploadID)
}
