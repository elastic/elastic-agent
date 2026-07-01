// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build linux && amd64

//TODO: arm64

package sensor

import (
	"fmt"

	"github.com/elastic/elastic-agent/internal/edot/receivers/quarkreceiver/internal/sensor/quark"

	"go.uber.org/zap"
)

type quarkQueue struct {
	logger *zap.Logger
	queue  *quark.Queue
}

func NewQueue(logger *zap.Logger) (Queue, error) {
	attr := quark.DefaultQueueAttr()
	attr.Flags |= quark.QQ_EBPF

	q, err := quark.OpenQueue(attr)
	if err != nil {
		return nil, fmt.Errorf("open quark queue: %w", err)
	}
	return &quarkQueue{logger: logger, queue: q}, nil
}

func (q *quarkQueue) GetEvent() ([]byte, bool) {
	b, ok, err := q.queue.GetEventAsECS()
	if err != nil {
		q.logger.Error("failed to get event", zap.Error(err))
		return nil, false
	}
	if !ok {
		return nil, false
	}
	return b, true
}

func (q *quarkQueue) Block() error { return q.queue.Block() }
func (q *quarkQueue) Close()       { q.queue.Close() }
