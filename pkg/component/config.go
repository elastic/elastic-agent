// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
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
		GoMaxProcs: uint64(c.GoMaxProcs), //nolint:gosec // will never be negative
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
		return nil, fmt.Errorf("decoding error: %w", err)
	}

	if err := setSource(result, cfg); err != nil {
		return nil, err
	}

	if err := updateDataStreamsFromSource(result, cfg); err != nil {
		return nil, fmt.Errorf("could not dedot 'data_stream': %w", err)
	}

	return result, nil
}

// dataStreamFields holds the data_stream values found in a source map, both from a nested
// `data_stream` dictionary and from flattened `data_stream.<field>` keys.
type dataStreamFields struct {
	DataStream struct {
		Dataset   string
		Type      string
		Namespace string
	}
}

// stringValue converts a scalar value into a string the way go-ucfg unpacks it into a string
// field. nil converts into the empty string. Non-scalar values are rejected.
func stringValue(v interface{}) (string, error) {
	switch t := v.(type) {
	case nil:
		return "", nil
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case []byte:
		return string(t), nil
	case json.Number:
		return string(t), nil
	case int, int8, int16, int32, int64:
		return strconv.FormatInt(reflect.ValueOf(t).Int(), 10), nil
	case uint, uint8, uint16, uint32, uint64:
		return strconv.FormatUint(reflect.ValueOf(t).Uint(), 10), nil
	case float32, float64:
		return strconv.FormatFloat(reflect.ValueOf(t).Float(), 'f', -1, 64), nil
	}
	return "", fmt.Errorf("unconvertible type '%T'", v)
}

// dataStreamFromSource extracts the data_stream fields directly from the source map without
// going through go-ucfg. Flattened keys (`data_stream.dataset`) take precedence over the nested
// dictionary, mirroring how go-ucfg merges them.
func dataStreamFromSource(source map[string]interface{}) (dataStreamFields, error) {
	var tmp dataStreamFields
	var err error
	if nested, ok := source["data_stream"].(map[string]interface{}); ok {
		if tmp.DataStream.Dataset, err = flattenedValue(nested["dataset"], "data_stream.dataset"); err != nil {
			return tmp, err
		}
		if tmp.DataStream.Type, err = flattenedValue(nested["type"], "data_stream.type"); err != nil {
			return tmp, err
		}
		if tmp.DataStream.Namespace, err = flattenedValue(nested["namespace"], "data_stream.namespace"); err != nil {
			return tmp, err
		}
	}
	for key, field := range map[string]*string{
		"data_stream.dataset":   &tmp.DataStream.Dataset,
		"data_stream.type":      &tmp.DataStream.Type,
		"data_stream.namespace": &tmp.DataStream.Namespace,
	} {
		if v, ok := source[key]; ok {
			if *field, err = flattenedValue(v, key); err != nil {
				return tmp, err
			}
		}
	}
	return tmp, nil
}

// flattenedValue converts a data_stream value into a string, rejecting non-scalar values the way
// unpacking them with go-ucfg did.
func flattenedValue(v interface{}, key string) (string, error) {
	s, err := stringValue(v)
	if err != nil {
		return "", fmt.Errorf("can not convert '%T' into 'string' accessing '%s'", v, key)
	}
	return s, nil
}

func deDotDataStream(ds *proto.DataStream, source map[string]interface{}) (*proto.DataStream, error) {
	if ds == nil {
		ds = &proto.DataStream{}
	}

	tmp, err := dataStreamFromSource(source)
	if err != nil {
		return nil, err
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

func updateDataStreamsFromSource(unitConfig *proto.UnitExpectedConfig, cfg map[string]interface{}) error {
	var err error
	unitConfig.DataStream, err = deDotDataStream(unitConfig.GetDataStream(), cfg)
	if err != nil {
		return fmt.Errorf("could not parse data_stream from input: %w", err)
	}

	// streams are decoded index-aligned with the "streams" list of the source config
	cfgStreams, _ := cfg["streams"].([]interface{})
	for i, stream := range unitConfig.Streams {
		var streamCfg map[string]interface{}
		if i < len(cfgStreams) {
			streamCfg, _ = cfgStreams[i].(map[string]interface{})
		}
		stream.DataStream, err = deDotDataStream(stream.GetDataStream(), streamCfg)
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
