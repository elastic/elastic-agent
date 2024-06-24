// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent/pkg/limits"
)

const (
	sourceFieldName = "source"
)

// For now the component limits match the agent limits.
// This might change in the future.
type ComponentLimits limits.LimitsConfig

func (c ComponentLimits) AsProto() *proto.ComponentLimits {
	// Use JSON marshaling-unmarshaling to convert cfg to mapstr
	data, err := json.Marshal(c)
	if err != nil {
		return nil
	}

	var s map[string]interface{}
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}

	source, err := structpb.NewStruct(s)
	if err != nil {
		return nil
	}

	return &proto.ComponentLimits{
		GoMaxProcs: uint64(c.GoMaxProcs),
		Source:     source,
	}
}

type ComponentConfig struct {
	Limits ComponentLimits
}

func (c ComponentConfig) AsProto() *proto.Component {
	return &proto.Component{
		Limits: c.Limits.AsProto(),
	}
}

// MustExpectedConfig returns proto.UnitExpectedConfig.
//
// Panics if the map[string]interface{} cannot be converted to proto.UnitExpectedConfig. This really should
// only be used by tests.
func MustExpectedConfig(cfg map[string]interface{}) *proto.UnitExpectedConfig {
	config, err := ExpectedConfig(cfg)
	if err != nil {
		panic(err)
	}
	return config
}

// ExpectedConfig converts a map[string]interface{} to a proto.UnitExpectedConfig.
func ExpectedConfig(cfg map[string]interface{}) (*proto.UnitExpectedConfig, error) {
	result := &proto.UnitExpectedConfig{}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		ZeroFields:           true,
		WeaklyTypedInput:     true,
		TagName:              "json",
		IgnoreUntaggedFields: true,
		Result:               result,
		MatchName: func(mapKey, fieldName string) bool {
			if fieldName == sourceFieldName {
				// never match for 'source' field that is set manually later
				return false
			}
			return strings.EqualFold(mapKey, fieldName)
		},
	})
	if err != nil {
		return nil, err
	}

	if err := decoder.Decode(cfg); err != nil {
		return nil, rewrapErr(err)
	}

	if err := setSource(result, cfg); err != nil {
		return nil, err
	}

	if err := updateDataStreamsFromSource(result); err != nil {
		return nil, fmt.Errorf("could not dedot 'data_stream': %w", err)
	}

	return result, nil
}

func deDotDataStream(ds *proto.DataStream, source *structpb.Struct) (*proto.DataStream, error) {
	if ds == nil {
		ds = &proto.DataStream{}
	}

	cfg, err := config.NewConfigFrom(source.AsMap())
	if err != nil {
		return nil, fmt.Errorf("cannot generate config from source field: %w", err)
	}

	// Create a temporary struct to unpack the configuration.
	// Unpack correctly handles any flattened fields like
	// data_stream.type. So all we need to do is to call Unpack,
	// ensure the DataStream does not have a different value,
	// them merge them both.
	tmp := struct {
		DataStream struct {
			Dataset   string `config:"dataset" yaml:"dataset"`
			Type      string `config:"type" yaml:"type"`
			Namespace string `config:"namespace" yaml:"namespace"`
		} `config:"data_stream" yaml:"data_stream"`
	}{}

	if err := cfg.Unpack(&tmp); err != nil {
		return nil, fmt.Errorf("cannot unpack source field into struct: %w", err)
	}

	if (ds.Dataset != tmp.DataStream.Dataset) && (ds.Dataset != "" && tmp.DataStream.Dataset != "") {
		return nil, errors.New("duplicated key 'datastream.dataset'")
	}

	if (ds.Type != tmp.DataStream.Type) && (ds.Type != "" && tmp.DataStream.Type != "") {
		return nil, errors.New("duplicated key 'datastream.type'")
	}

	if (ds.Namespace != tmp.DataStream.Namespace) && (ds.Namespace != "" && tmp.DataStream.Namespace != "") {
		return nil, errors.New("duplicated key 'datastream.namespace'")
	}

	ret := &proto.DataStream{
		Dataset:   valueOrDefault(tmp.DataStream.Dataset, ds.Dataset),
		Type:      valueOrDefault(tmp.DataStream.Type, ds.Type),
		Namespace: valueOrDefault(tmp.DataStream.Namespace, ds.Namespace),
		Source:    ds.GetSource(),
	}

	return ret, nil
}

// valueOrDefault returns b if a is an empty string
func valueOrDefault(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

func updateDataStreamsFromSource(unitConfig *proto.UnitExpectedConfig) error {
	var err error
	unitConfig.DataStream, err = deDotDataStream(unitConfig.GetDataStream(), unitConfig.GetSource())
	if err != nil {
		return fmt.Errorf("could not parse data_stream from input: %w", err)
	}

	for i, stream := range unitConfig.Streams {
		stream.DataStream, err = deDotDataStream(stream.GetDataStream(), stream.GetSource())
		if err != nil {
			return fmt.Errorf("could not parse data_stream from stream [%d]: %w",
				i, err)
		}
	}

	return nil
}

func setSource(val interface{}, cfg map[string]interface{}) error {
	// find the source field on the val
	resVal := reflect.ValueOf(val).Elem()
	sourceFieldByTag, ok := getSourceField(resVal.Type())
	if !ok {
		return fmt.Errorf("%T does not define a source field", val)
	}
	sourceField := resVal.FieldByName(sourceFieldByTag.Name)
	if !sourceField.CanSet() {
		return fmt.Errorf("%T.source cannot be set", val)
	}

	// create the source (as the original source is always sent)
	source, err := structpb.NewStruct(cfg)
	if err != nil {
		return err
	}
	sourceField.Set(reflect.ValueOf(source))

	// look into every field that could also have a source field
	for i := 0; i < resVal.NumField(); i++ {
		typeField := resVal.Type().Field(i)
		if !typeField.IsExported() {
			continue
		}
		jsonName := getJSONFieldName(typeField)
		if jsonName == "" || jsonName == sourceFieldName {
			// skip fields without a json name or named 'source'
			continue
		}
		cfgVal, ok := cfg[jsonName]
		if !ok {
			// doesn't exist in config (so no source)
			continue
		}
		valField := resVal.Field(i)
		valType := valField.Type()
		switch valType.Kind() {
		case reflect.Ptr:
			cfgDict, ok := cfgVal.(map[string]interface{})
			if ok && hasSourceField(valType.Elem()) {
				err := setSource(valField.Interface(), cfgDict)
				if err != nil {
					return fmt.Errorf("setting source for field %s failed: %w", jsonName, err)
				}
			}
		case reflect.Slice:
			cfgSlice, ok := cfgVal.([]interface{})
			if ok {
				valElem := reflect.ValueOf(valField.Interface())
				for j := 0; j < valElem.Len(); j++ {
					valIdx := valElem.Index(j)
					cfgDict, ok := cfgSlice[j].(map[string]interface{})
					if ok && hasSourceField(valIdx.Elem().Type()) {
						err := setSource(valIdx.Interface(), cfgDict)
						if err != nil {
							return fmt.Errorf("setting source for field %s.%d failed: %w", jsonName, j, err)
						}
					}
				}
			}
		}
	}
	return nil
}

func getSourceField(t reflect.Type) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		typeField := t.Field(i)
		jsonName := getJSONFieldName(typeField)
		if typeField.IsExported() && jsonName == sourceFieldName {
			return typeField, true
		}
	}
	return reflect.StructField{}, false
}

func hasSourceField(t reflect.Type) bool {
	_, ok := getSourceField(t)
	return ok
}

func getJSONFieldName(field reflect.StructField) string {
	tag, ok := field.Tag.Lookup("json")
	if !ok {
		return ""
	}
	if tag == "" {
		return ""
	}
	split := strings.Split(tag, ",")
	return strings.TrimSpace(split[0])
}

func rewrapErr(err error) error {
	var me *mapstructure.Error
	if !errors.As(err, &me) {
		return err
	}
	errs := me.WrappedErrors()
	points := make([]string, 0, len(errs))
	for _, e := range errs {
		points = append(points, e.Error())
	}
	return fmt.Errorf("%d decoding error(s): %s", len(errs), strings.Join(points, ", "))
}
