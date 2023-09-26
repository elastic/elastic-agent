// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/elastic/elastic-agent-libs/mapstr"
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

// TemplateResponse is the body of a template data request
type TemplateResponse struct {
	IndexTemplates []Template `json:"index_templates"`
}

// Template is an individual template
type Template struct {
	Name          string                 `json:"name"`
	IndexTemplate map[string]interface{} `json:"index_template"`
}

// Pipeline is an individual pipeline
type Pipeline struct {
	Description string                   `json:"description"`
	Processors  []map[string]interface{} `json:"processors"`
}

// Ping returns basic ES info
type Ping struct {
	Name        string  `json:"name"`
	ClusterName string  `json:"cluster_name"`
	ClusterUUID string  `json:"cluster_uuid"`
	Version     Version `json:"version"`
}

// Version contains version and build info from an ES ping
type Version struct {
	Number      string `json:"number"`
	BuildFlavor string `json:"build_flavor"`
}

// APIKeyRequest contains the needed data to create an API key in Elasticsearch
type APIKeyRequest struct {
	Name            string   `json:"name"`
	Expiration      string   `json:"expiration"`
	RoleDescriptors mapstr.M `json:"role_descriptors,omitempty"`
	Metadata        mapstr.M `json:"metadata,omitempty"`
}

// APIKeyResponse contains the response data for an API request
type APIKeyResponse struct {
	Id         string `json:"id"`
	Name       string `json:"name"`
	Expiration int    `json:"expiration"`
	APIKey     string `json:"api_key"`
	Encoded    string `json:"encoded"`
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

// CreateAPIKey creates an API key with the given request data
func CreateAPIKey(ctx context.Context, client elastictransport.Interface, req APIKeyRequest) (APIKeyResponse, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(req)
	if err != nil {
		return APIKeyResponse{}, fmt.Errorf("error creating ES query: %w", err)
	}

	apiReq := esapi.SecurityCreateAPIKeyRequest{Body: &buf}
	resp, err := apiReq.Do(ctx, client)
	if err != nil {
		return APIKeyResponse{}, fmt.Errorf("error creating API key: %w", err)
	}
	resultBuf, err := handleResponseRaw(resp)
	if err != nil {
		return APIKeyResponse{}, fmt.Errorf("error handling HTTP response: %w", err)
	}

	parsed := APIKeyResponse{}
	err = json.Unmarshal(resultBuf, &parsed)
	if err != nil {
		return parsed, fmt.Errorf("error unmarshaling json response: %w", err)
	}

	return parsed, nil
}

// FindMatchingLogLines returns any logs with message fields that match the given line
func FindMatchingLogLines(client elastictransport.Interface, namespace, line string) (Documents, error) {
	return FindMatchingLogLinesWithContext(context.Background(), client, namespace, line)
}

// GetLatestDocumentMatchingQuery returns the last document that matches the given query.
// the query field is inserted into a simple `query` POST request
func GetLatestDocumentMatchingQuery(ctx context.Context, client elastictransport.Interface, query map[string]interface{}, indexPattern string) (Documents, error) {
	queryRaw := map[string]interface{}{
		"query": query,
		"sort": map[string]interface{}{
			"timestamp": "desc",
		},
		"size": 1,
	}
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(queryRaw)
	if err != nil {
		return Documents{}, fmt.Errorf("error creating ES query: %w", err)
	}

	return performQueryForRawQuery(ctx, queryRaw, indexPattern, client)
}

// GetIndexTemplatesForPattern lists all index templates on the system
func GetIndexTemplatesForPattern(ctx context.Context, client elastictransport.Interface, name string) (TemplateResponse, error) {
	req := esapi.IndicesGetIndexTemplateRequest{Name: name}
	resp, err := req.Do(ctx, client)
	if err != nil {
		return TemplateResponse{}, fmt.Errorf("error fetching index templates: %w", err)
	}

	resultBuf, err := handleResponseRaw(resp)
	if err != nil {
		return TemplateResponse{}, fmt.Errorf("error handling HTTP response: %w", err)
	}
	parsed := TemplateResponse{}

	err = json.Unmarshal(resultBuf, &parsed)
	if err != nil {
		return TemplateResponse{}, fmt.Errorf("error unmarshaling json response: %w", err)
	}

	return parsed, nil
}

// DeleteIndexTemplatesDataStreams deletes any data streams, then associcated index templates.
func DeleteIndexTemplatesDataStreams(ctx context.Context, client elastictransport.Interface, name string) error {
	req := esapi.IndicesDeleteDataStreamRequest{Name: []string{name}, ExpandWildcards: "all,hidden"}
	resp, err := req.Do(ctx, client)
	if err != nil {
		return fmt.Errorf("error deleting data streams: %w", err)
	}
	_, err = handleResponseRaw(resp)
	if err != nil {
		return fmt.Errorf("error handling HTTP response for data stream delete: %w", err)
	}

	patternReq := esapi.IndicesDeleteIndexTemplateRequest{Name: name}
	resp, err = patternReq.Do(ctx, client)
	if err != nil {
		return fmt.Errorf("error deleting index templates: %w", err)
	}
	_, err = handleResponseRaw(resp)
	if err != nil {
		return fmt.Errorf("error handling HTTP response for index template delete: %w", err)
	}
	return nil
}

// GetPipelines returns a list of installed pipelines that match the given name/pattern
func GetPipelines(ctx context.Context, client elastictransport.Interface, name string) (map[string]Pipeline, error) {
	req := esapi.IngestGetPipelineRequest{PipelineID: name}
	resp, err := req.Do(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("error fetching index templates: %w", err)
	}
	resultBuf, err := handleResponseRaw(resp)
	if err != nil {
		return nil, fmt.Errorf("error handling HTTP response: %w", err)
	}

	parsed := map[string]Pipeline{}
	err = json.Unmarshal(resultBuf, &parsed)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json response: %w", err)
	}
	return parsed, nil
}

// DeletePipelines deletes all pipelines that match the given pattern
func DeletePipelines(ctx context.Context, client elastictransport.Interface, name string) error {
	req := esapi.IngestDeletePipelineRequest{PipelineID: name}
	resp, err := req.Do(ctx, client)
	if err != nil {
		return fmt.Errorf("error deleting index template")
	}
	_, err = handleResponseRaw(resp)
	if err != nil {
		return fmt.Errorf("error handling HTTP response: %w", err)
	}
	return nil
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

	return performQueryForRawQuery(ctx, queryRaw, "*ds-logs*", client)

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

	return performQueryForRawQuery(ctx, queryRaw, "*ds-logs*", client)

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

	return performQueryForRawQuery(ctx, indexQuery, "*ds-logs*", client)
}

// GetPing performs a basic ping and returns ES config info
func GetPing(ctx context.Context, client elastictransport.Interface) (Ping, error) {
	req := esapi.InfoRequest{}
	resp, err := req.Do(ctx, client)
	if err != nil {
		return Ping{}, fmt.Errorf("error in ping request")
	}

	respData, err := handleResponseRaw(resp)
	if err != nil {
		return Ping{}, fmt.Errorf("error in HTTP response: %w", err)
	}
	pingData := Ping{}
	err = json.Unmarshal(respData, &pingData)
	if err != nil {
		return pingData, fmt.Errorf("error unmarshalling JSON: %w", err)
	}
	return pingData, nil

}

func performQueryForRawQuery(ctx context.Context, queryRaw map[string]interface{}, index string, client elastictransport.Interface) (Documents, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(queryRaw)
	if err != nil {
		return Documents{}, fmt.Errorf("error creating ES query: %w", err)
	}

	es := esapi.New(client)
	res, err := es.Search(
		es.Search.WithIndex(index),
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
	resultBuf, err := handleResponseRaw(res)
	if err != nil {
		return Documents{}, fmt.Errorf("error in HTTP query: %w", err)
	}
	respData := Documents{}

	err = json.Unmarshal(resultBuf, &respData)
	if err != nil {
		return Documents{}, fmt.Errorf("error unmarshaling response: %w", err)
	}

	return respData, err
}

func handleResponseRaw(res *esapi.Response) ([]byte, error) {
	if res.StatusCode >= 300 || res.StatusCode < 200 {
		return nil, fmt.Errorf("non-200 return code: %v, response: '%s'", res.StatusCode, res.String())
	}

	resultBuf, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}
	return resultBuf, nil
}
