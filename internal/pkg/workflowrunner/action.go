// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"
)

const (
	dataStreamType    = "logs"
	dataStreamDataset = "workflow_runner.http"
	defaultNamespace  = "default"

	// maxIndexReserve is the most time held back from the HTTP call so the
	// result can still be indexed before the agent's action timeout fires.
	maxIndexReserve = 10 * time.Second
)

// target returns the indexer and namespace the action should write to.
type targetFunc func() (Indexer, string)

// httpAction implements the elastic-agent-client Action interface for workflow/http.
type httpAction struct {
	logger   zerolog.Logger
	executor *Executor
	store    *Store
	target   targetFunc
	inflight singleflight.Group
}

func (a *httpAction) Name() string { return ActionName }

// Execute runs one workflow HTTP step. It returns an error only when the action
// itself is invalid; failures of the HTTP call or of indexing are reported in
// the returned map's "error" key so the agent still acks the result fields.
func (a *httpAction) Execute(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	p, err := parseAction(params)
	if err != nil {
		a.logger.Warn().Err(err).Msg("rejected workflow/http action")
		return nil, err
	}

	ack, _, _ := a.inflight.Do(p.ID, func() (interface{}, error) {
		if prior, ok := a.store.Get(p.ID); ok {
			a.logger.Info().Str("action.id", p.ID).Msg("workflow/http action already completed; returning stored result")
			return prior, nil
		}
		ack := a.run(ctx, p)
		if err := a.store.Put(p.ID, ack); err != nil {
			a.logger.Error().Err(err).Str("action.id", p.ID).Msg("failed to record completed workflow/http action")
		}
		return ack, nil
	})
	return ack.(map[string]interface{}), nil
}

func (a *httpAction) run(ctx context.Context, p parsedAction) map[string]interface{} {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	reserve := min(p.timeout/5, maxIndexReserve)
	httpCtx, httpCancel := context.WithTimeout(ctx, p.timeout-reserve)
	res := a.executor.Do(httpCtx, Call{
		Method:           p.Data.Request.Method,
		Target:           p.target,
		Headers:          p.Data.Request.Headers,
		Body:             p.body,
		MaxRedirects:     p.Data.Request.MaxRedirects,
		MaxResponseBytes: p.Data.Request.MaxResponseBytes,
	})
	httpCancel()

	log := a.logger.Info()
	if res.Error != "" {
		log = a.logger.Warn().Str("error.message", res.Error)
	}
	log.Str("action.id", p.ID).
		Str("url.domain", p.target.Hostname()).
		Int("http.response.status_code", res.StatusCode).
		Dur("event.duration", res.End.Sub(res.Start)).
		Msg("workflow/http request finished")

	ack := map[string]interface{}{
		"started_at":   res.Start.Format(time.RFC3339Nano),
		"completed_at": res.End.Format(time.RFC3339Nano),
	}
	if res.StatusCode != 0 {
		ack["status_code"] = res.StatusCode
	}

	indexer, namespace := a.target()
	if indexer == nil {
		ack["error"] = joinErrors(res.Error, "no elasticsearch output is configured for the workflow runner")
		return ack
	}
	index := dataStreamName(namespace)
	if err := indexer.Index(ctx, index, p.ID, resultDocument(p, res, namespace)); err != nil {
		a.logger.Error().Err(err).Str("action.id", p.ID).Msg("failed to store workflow/http result")
		ack["error"] = joinErrors(res.Error, err.Error())
		return ack
	}
	ack["result_index"] = index
	ack["result_id"] = p.ID
	if res.Error != "" {
		ack["error"] = res.Error
	}
	return ack
}

func dataStreamName(namespace string) string {
	if namespace == "" {
		namespace = defaultNamespace
	}
	return dataStreamType + "-" + dataStreamDataset + "-" + namespace
}

// resultDocument is the document Kibana reads by action id. It records the
// response and identifies the target host, but never the request headers or body.
func resultDocument(p parsedAction, res Result, namespace string) map[string]interface{} {
	if namespace == "" {
		namespace = defaultNamespace
	}
	outcome := "success"
	if res.Error != "" {
		outcome = "failure"
	}
	doc := map[string]interface{}{
		"@timestamp": res.End.Format(time.RFC3339Nano),
		"data_stream": map[string]interface{}{
			"type":      dataStreamType,
			"dataset":   dataStreamDataset,
			"namespace": namespace,
		},
		"event": map[string]interface{}{
			"start":    res.Start.Format(time.RFC3339Nano),
			"end":      res.End.Format(time.RFC3339Nano),
			"duration": res.End.Sub(res.Start).Nanoseconds(),
			"outcome":  outcome,
		},
		"workflow": map[string]interface{}{
			"action_id":    p.ID,
			"space_id":     p.Data.SpaceID,
			"execution_id": p.Data.ExecutionID,
			"step_id":      p.Data.StepID,
		},
		"url": map[string]interface{}{
			"scheme": p.target.Scheme,
			"domain": p.target.Hostname(),
		},
		"http": map[string]interface{}{
			"request": map[string]interface{}{
				"method": p.Data.Request.Method,
			},
		},
	}
	if res.StatusCode != 0 {
		doc["http"].(map[string]interface{})["response"] = map[string]interface{}{
			"status_code": res.StatusCode,
			"headers":     res.Headers,
			"body": map[string]interface{}{
				"content":   res.Body,
				"bytes":     res.BodyBytes,
				"truncated": res.Truncated,
			},
		}
	}
	if res.Error != "" {
		doc["error"] = map[string]interface{}{"message": res.Error}
	}
	return doc
}

func joinErrors(first, second string) string {
	if first == "" {
		return second
	}
	return first + "; " + second
}
