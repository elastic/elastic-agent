// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
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
			Err: errors.New("decoding error: 'meta' expected a map or struct, got \"slice\""),
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
				// protocmp.Transform ensures we do not compare any internal
				// protobuf fields
				if !cmp.Equal(scenario.Expected, observed, protocmp.Transform()) {
					t.Errorf("mismatch (-want +got) \n%s",
						cmp.Diff(scenario.Expected, observed, protocmp.Transform()))
				}
			}
		})
	}
}

func TestExpectedConfigFlattenedDataStream(t *testing.T) {
	cfg := map[string]interface{}{
		"id":                  "input-1",
		"type":                "filestream",
		"data_stream.dataset": "unit.dataset",
		"data_stream": map[string]interface{}{
			"namespace": "unit.namespace",
		},
		"streams": []interface{}{
			map[string]interface{}{
				"id":                    "stream-1",
				"data_stream.type":      "logs",
				"data_stream.namespace": "stream.namespace",
				"data_stream":           map[string]interface{}{"dataset": "stream.dataset"},
			},
		},
	}
	got, err := ExpectedConfig(cfg)
	require.NoError(t, err)
	require.Equal(t, "unit.dataset", got.DataStream.Dataset)
	require.Equal(t, "unit.namespace", got.DataStream.Namespace)
	require.Len(t, got.Streams, 1)
	require.Equal(t, "stream.dataset", got.Streams[0].DataStream.Dataset)
	require.Equal(t, "logs", got.Streams[0].DataStream.Type)
	require.Equal(t, "stream.namespace", got.Streams[0].DataStream.Namespace)

	// conflicting nested and flattened values must still be rejected
	cfg["data_stream"] = map[string]interface{}{"dataset": "other"}
	_, err = ExpectedConfig(cfg)
	require.ErrorContains(t, err, "duplicated key 'datastream.dataset'")

	// non-scalar values are rejected, as unpacking them with go-ucfg did
	cfg["data_stream"] = map[string]interface{}{}
	cfg["data_stream.dataset"] = []interface{}{"x"}
	_, err = ExpectedConfig(cfg)
	require.ErrorContains(t, err, "can not convert '[]interface {}' into 'string' accessing 'data_stream.dataset'")
}
