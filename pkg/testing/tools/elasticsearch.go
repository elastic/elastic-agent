package tools

import (
	"bytes"
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

type Documents struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Hits     Hits `json:"hits"`
}

type Hits struct {
	Hits  []ESDoc       `json:"hits"`
	Total TotalDocCount `json:"total"`
}

type TotalDocCount struct {
	Value    int    `json:"value"`
	Relation string `json:"relation"`
}

type ESDoc struct {
	Index  string                 `json:"_index"`
	Score  float64                `json:"_score"`
	Source map[string]interface{} `json:"_source"`
}

// GetAllindicies returns a list of indicies on the target ES instance
func GetAllindicies(client elastictransport.Interface) ([]Index, error) {
	return GetIndicesWithContext(context.Background(), client, []string{})
}

// GetIndicesWithContext returns a list of indicies on the target ES instance with the provided context
func GetIndicesWithContext(ctx context.Context, client elastictransport.Interface, indicies []string) ([]Index, error) {
	req := esapi.CatIndicesRequest{Format: "json", Bytes: "b"}
	if len(indicies) > 0 {
		req.Index = indicies
		req.ExpandWildcards = "all"
	}
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

// GetLogsForDatastream returns any logs associated with the datastream
func GetLogsForDatastream(client elastictransport.Interface, index string) (Documents, error) {
	indexQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"match": map[string]interface{}{
				"data_stream.dataset": index,
			},
		},
	}

	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(indexQuery)
	if err != nil {
		return Documents{}, fmt.Errorf("error creating ES query: %w", err)
	}

	es := esapi.New(client)
	res, err := es.Search(
		es.Search.WithIndex("*.ds-logs*"),
		es.Search.WithExpandWildcards("all"),
		es.Search.WithBody(&buf),
		es.Search.WithTrackTotalHits(true),
		es.Search.WithPretty(),
	)
	if err != nil {
		return Documents{}, fmt.Errorf("error performing ES search: %w", err)
	}

	if res.StatusCode >= 300 || res.StatusCode < 200 {
		return Documents{}, fmt.Errorf("non-200 return code: %v, response: '%s'", res.StatusCode, res.String())
	}

	resultBuf, err := io.ReadAll(res.Body)
	if err != nil {
		return Documents{}, fmt.Errorf("error reading response body: %w", err)
	}
	respData := Documents{}

	err = json.Unmarshal(resultBuf, &respData)
	if err != nil {
		return Documents{}, fmt.Errorf("error unmarshaling response: %w", err)
	}

	return respData, err
}

// GetDocumentsInIndex returns a sample of documents for an index
func GetDocumentsInIndex(client elastictransport.Interface, index string) (Documents, error) {
	testCount := 10
	req := esapi.SearchRequest{Index: []string{index}, Size: &testCount, ExpandWildcards: "all"}

	resp, err := req.Do(context.Background(), client)
	if err != nil {
		return Documents{}, fmt.Errorf("error fetching documents: %w", err)
	}

	if resp.StatusCode >= 300 || resp.StatusCode < 200 {
		return Documents{}, fmt.Errorf("non-200 return code: %v, response: '%s'", resp.StatusCode, resp.String())
	}

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return Documents{}, fmt.Errorf("error reading response body: %w", err)
	}
	respData := Documents{}

	err = json.Unmarshal(buf, &respData)
	if err != nil {
		return Documents{}, fmt.Errorf("error unmarshaling response: %w", err)
	}

	return respData, nil
}
