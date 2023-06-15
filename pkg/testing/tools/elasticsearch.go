package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/elastic/elastic-transport-go/v8/elastictransport"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

// Index is the data associated with a single index from _cat/indicies
type Index struct {
	Health                string     `json:"health"`
	Status                string     `json:"status"`
	Index                 string     `json:"index"`
	UUID                  string     `json:"uuid"`
	Primary               CatIntData `json:"pri"`
	Replicated            CatIntData `json:"rep"`
	DocsCount             CatIntData `json:"docs.count"`
	DocsDeleted           CatIntData `json:"docs.deleted"`
	StoreSizeBytes        CatIntData `json:"store.size"`
	PrimaryStoreSizeBytes CatIntData `json:"pri.store.size"`
}

// CatIntData represents a shard/doc/byte count in Index{}
type CatIntData int64

// UnmarshalJSON implements the custom unmarshal JSON interface
// kind of dumb, but ES wraps ints in quotes, so we have to manually turn them into ints
func (s *CatIntData) UnmarshalJSON(b []byte) error {
	cleaned := strings.Trim(string(b), "\"")
	res, err := strconv.ParseInt(cleaned, 10, 64)
	if err != nil {
		return fmt.Errorf("error unmarshalling JSON for string '%s': %w", cleaned, err)
	}
	*s = CatIntData(res)
	return nil
}

// GetIndices returns a list of indicies on the target ES instance
func GetIndices(client elastictransport.Interface) ([]Index, error) {
	return GetIndicesWithContext(context.Background(), client)
}

// GetIndicesWithContext returns a list of indicies on the target ES instance with the provided context
func GetIndicesWithContext(ctx context.Context, client elastictransport.Interface) ([]Index, error) {
	req := esapi.CatIndicesRequest{Format: "json", Bytes: "b"}
	resp, err := req.Do(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("error performing cat query: %w", err)
	}
	if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		return nil, fmt.Errorf("non-200 return code: %v, response: '%s'", resp.StatusCode, resp.String())
	}
	buf, err := io.ReadAll(resp.Body)
	respData := []Index{}
	err = json.Unmarshal(buf, &respData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}
	return respData, nil
}

// GetDocumentsInIndex returns a sample of documents for an index
func GetDocumentsInIndex(client elastictransport.Interface, index string) (string, error) {
	testCount := 10
	req := esapi.SearchRequest{Index: []string{index}, Size: &testCount}

	resp, err := req.Do(context.Background(), client)
	if err != nil {
		return "", fmt.Errorf("error fetching documents: %w", err)
	}

	if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		return "", fmt.Errorf("non-200 return code: %v, response: '%s'", resp.StatusCode, resp.String())
	}

	return resp.String(), nil
}
