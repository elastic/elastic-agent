// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
)

func TestExpectedConfig(t *testing.T) {
	scenarios := []struct {
		Name      string
		Config    map[string]interface{}
		Err       error
		Expected  *proto.UnitExpectedConfig
		SetSource func(map[string]interface{}, *proto.UnitExpectedConfig) error
	}{
		{
			Name: "Full",
			Config: map[string]interface{}{
				"id":       "simple-0",
				"type":     "simple",
				"name":     "simple",
				"revision": 1,
				"meta": map[string]interface{}{
					"package": map[string]interface{}{
						"name":    "simple",
						"version": "1.0.0",
						"extra": map[string]interface{}{
							"field": "package",
						},
					},
					"extra": map[string]interface{}{
						"field": "meta",
					},
				},
				"data_stream": map[string]interface{}{
					"dataset":   "other",
					"type":      "simple",
					"namespace": "default",
					"extra": map[string]interface{}{
						"field": "data_stream",
					},
				},
				"streams": []interface{}{
					map[string]interface{}{
						"id": "simple-stream-0",
						"data_stream": map[string]interface{}{
							"dataset":   "other",
							"type":      "simple",
							"namespace": "default-0",
							"extra": map[string]interface{}{
								"field": "data_stream",
							},
						},
						"extra": map[string]interface{}{
							"field": "stream-0",
						},
					},
					map[string]interface{}{
						"id": "simple-stream-1",
						"data_stream": map[string]interface{}{
							"dataset":   "other",
							"type":      "simple",
							"namespace": "default-1",
							"extra": map[string]interface{}{
								"field": "data_stream",
							},
						},
						"extra": map[string]interface{}{
							"field": "stream-1",
						},
					},
				},
				"extra": map[string]interface{}{
					"field": "config",
				},
			},
			Expected: &proto.UnitExpectedConfig{
				Source:   nil,
				Id:       "simple-0",
				Type:     "simple",
				Name:     "simple",
				Revision: 1,
				Meta: &proto.Meta{
					Source: nil,
					Package: &proto.Package{
						Source:  nil,
						Name:    "simple",
						Version: "1.0.0",
					},
				},
				DataStream: &proto.DataStream{
					Source:    nil,
					Dataset:   "other",
					Type:      "simple",
					Namespace: "default",
				},
				Streams: []*proto.Stream{
					{
						Source: nil,
						Id:     "simple-stream-0",
						DataStream: &proto.DataStream{
							Source:    nil,
							Dataset:   "other",
							Type:      "simple",
							Namespace: "default-0",
						},
					},
					{
						Source: nil,
						Id:     "simple-stream-1",
						DataStream: &proto.DataStream{
							Source:    nil,
							Dataset:   "other",
							Type:      "simple",
							Namespace: "default-1",
						},
					},
				},
			},
			SetSource: func(cfg map[string]interface{}, expected *proto.UnitExpectedConfig) error {
				source, err := structpb.NewStruct(cfg)
				if err != nil {
					return err
				}
				expected.Source = source

				meta, err := structpb.NewStruct(cfg["meta"].(map[string]interface{}))
				if err != nil {
					return err
				}
				expected.Meta.Source = meta

				pack, err := structpb.NewStruct(cfg["meta"].(map[string]interface{})["package"].(map[string]interface{}))
				if err != nil {
					return err
				}
				expected.Meta.Package.Source = pack

				ds, err := structpb.NewStruct(cfg["data_stream"].(map[string]interface{}))
				if err != nil {
					return err
				}
				expected.DataStream.Source = ds

				for i, stream := range cfg["streams"].([]interface{}) {
					ss, err := structpb.NewStruct(stream.(map[string]interface{}))
					if err != nil {
						return err
					}
					expected.Streams[i].Source = ss

					sds, err := structpb.NewStruct(stream.(map[string]interface{})["data_stream"].(map[string]interface{}))
					if err != nil {
						return err
					}
					expected.Streams[i].DataStream.Source = sds
				}
				return nil
			},
		},
		{
			Name: "Invalid",
			Config: map[string]interface{}{
				"id":       "simple-0",
				"type":     "simple",
				"name":     "simple",
				"revision": 1,
				"meta": []interface{}{
					map[string]interface{}{
						"invalid": "meta",
					},
				},
			},
			Err: errors.New("1 decoding error(s): 'meta' expected a map, got 'slice'"),
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			if scenario.SetSource != nil {
				err := scenario.SetSource(scenario.Config, scenario.Expected)
				require.NoError(t, err)
			}

			observed, err := ExpectedConfig(scenario.Config)
			if scenario.Err != nil {
				assert.Equal(t, err.Error(), scenario.Err.Error())
			} else {
				require.NoError(t, err)
				assert.EqualValues(t, scenario.Expected, observed)
			}
		})
	}
}
