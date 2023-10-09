// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package estools

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

// Documents represents the complete response from an ES query
type Documents struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Hits     Hits `json:"hits"`
}

// Hits returns the matching documents from an ES query
type Hits struct {
	Hits  []ESDoc       `json:"hits"`
	Total TotalDocCount `json:"total"`
}

// TotalDocCount contains metadata for the ES response
type TotalDocCount struct {
	Value    int    `json:"value"`
	Relation string `json:"relation"`
}

// ESDoc contains the documents returned by an ES query
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
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}
	respData := []Index{}
	err = json.Unmarshal(buf, &respData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}
	return respData, nil
}

// FindMatchingLogLines returns any logs with message fields that match the given line
func FindMatchingLogLines(client elastictransport.Interface, namespace, line string) (Documents, error) {
	return FindMatchingLogLinesWithContext(context.Background(), client, namespace, line)
}

// FindMatchingLogLinesWithContext returns any logs with message fields that match the given line
func FindMatchingLogLinesWithContext(ctx context.Context, client elastictransport.Interface, namespace, line string) (Documents, error) {
	queryRaw := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"match_phrase": map[string]interface{}{
							"message": line,
						},
					},
					{
						"term": map[string]interface{}{
							"data_stream.namespace": map[string]interface{}{
								"value": namespace,
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(queryRaw)
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
		es.Search.WithContext(ctx),
	)
	if err != nil {
		return Documents{}, fmt.Errorf("error performing ES search: %w", err)
	}

	return handleDocsResponse(res)
}

// CheckForErrorsInLogs checks to see if any error-level lines exist
// excludeStrings can be used to remove any particular error strings from logs
func CheckForErrorsInLogs(client elastictransport.Interface, namespace string, excludeStrings []string) (Documents, error) {
	return CheckForErrorsInLogsWithContext(context.Background(), client, namespace, excludeStrings)
}

// CheckForErrorsInLogsWithContext checks to see if any error-level lines exist
// excludeStrings can be used to remove any particular error strings from logs
func CheckForErrorsInLogsWithContext(ctx context.Context, client elastictransport.Interface, namespace string, excludeStrings []string) (Documents, error) {
	queryRaw := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"match": map[string]interface{}{
							"log.level": "error",
						},
					},
					{
						"term": map[string]interface{}{
							"data_stream.namespace": map[string]interface{}{
								"value": namespace,
							},
						},
					},
				},
			},
		},
	}

	if len(excludeStrings) > 0 {
		excludeStatements := []map[string]interface{}{}
		for _, ex := range excludeStrings {
			excludeStatements = append(excludeStatements, map[string]interface{}{
				"match_phrase": map[string]interface{}{
					"message": ex,
				},
			})
		}
		queryRaw = map[string]interface{}{
			"query": map[string]interface{}{
				"bool": map[string]interface{}{
					"must": []map[string]interface{}{
						{
							"match": map[string]interface{}{
								"log.level": "error",
							},
						},
					},
					"must_not": excludeStatements,
				},
			},
		}
	}

	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(queryRaw)
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
		es.Search.WithContext(ctx),
	)
	if err != nil {
		return Documents{}, fmt.Errorf("error performing ES search: %w", err)
	}

	return handleDocsResponse(res)
}

// GetLogsForDatastream returns any logs associated with the datastream
func GetLogsForDatastream(client elastictransport.Interface, index string) (Documents, error) {
	return GetLogsForDatastreamWithContext(context.Background(), client, index)
}

// GetLogsForAgentID returns any logs associated with the agent ID
func GetLogsForAgentID(client elastictransport.Interface, id string) (Documents, error) {
	indexQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"match": map[string]interface{}{
				"data_stream.dataset": "elastic_agent.*",
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
		es.Search.WithContext(context.Background()),
		es.Search.WithQuery(fmt.Sprintf(`elastic_agent.id:%s`, id)),
		// magic number, we try to get all entries it helps debugging test failures
		es.Search.WithSize(300),
	)
	if err != nil {
		return Documents{}, fmt.Errorf("error performing ES search: %w", err)
	}

	return handleDocsResponse(res)
}

// GetLogsForDatastreamWithContext returns any logs associated with the datastream
func GetLogsForDatastreamWithContext(ctx context.Context, client elastictransport.Interface, index string) (Documents, error) {
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
		es.Search.WithContext(ctx),
	)
	if err != nil {
		return Documents{}, fmt.Errorf("error performing ES search: %w", err)
	}

	return handleDocsResponse(res)
}

func handleDocsResponse(res *esapi.Response) (Documents, error) {
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
