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

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/pkg/limits"
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
//
// The complete map is converted into the message's source once; the sources of the nested
// messages (meta, package, data_stream and streams) are the matching parts of it rather than
// separate conversions. The typed fields are read directly from the map: keys are matched
// exactly or, failing that, case-insensitively, and scalar values are converted the way a weakly
// typed decoder would.
func ExpectedConfig(cfg map[string]interface{}) (*proto.UnitExpectedConfig, error) {
	source, err := structpb.NewStruct(cfg)
	if err != nil {
		return nil, err
	}
	result := &proto.UnitExpectedConfig{Source: source}
	if result.Id, err = stringField(cfg, "id", ""); err != nil {
		return nil, decodeError(err)
	}
	if result.Type, err = stringField(cfg, "type", ""); err != nil {
		return nil, decodeError(err)
	}
	if result.Name, err = stringField(cfg, "name", ""); err != nil {
		return nil, decodeError(err)
	}
	if result.Revision, err = uint64Field(cfg, "revision", ""); err != nil {
		return nil, decodeError(err)
	}
	if metaKey, metaRaw, ok := lookupField(cfg, "meta"); ok && metaRaw != nil {
		metaMap, ok := metaRaw.(map[string]interface{})
		if !ok {
			return nil, decodeError(unexpectedTypeError("meta", "a map or struct", metaRaw))
		}
		result.Meta = &proto.Meta{Source: source.Fields[metaKey].GetStructValue()}
		if pkgKey, pkgRaw, ok := lookupField(metaMap, "package"); ok && pkgRaw != nil {
			pkgMap, ok := pkgRaw.(map[string]interface{})
			if !ok {
				return nil, decodeError(unexpectedTypeError("meta.package", "a map or struct", pkgRaw))
			}
			result.Meta.Package = &proto.Package{Source: result.Meta.Source.Fields[pkgKey].GetStructValue()}
			if result.Meta.Package.Name, err = stringField(pkgMap, "name", "meta.package."); err != nil {
				return nil, decodeError(err)
			}
			if result.Meta.Package.Version, err = stringField(pkgMap, "version", "meta.package."); err != nil {
				return nil, decodeError(err)
			}
		}
	}
	if result.DataStream, err = dataStreamField(cfg, source, ""); err != nil {
		return nil, err
	}

	if streamsKey, streamsRaw, ok := lookupField(cfg, "streams"); ok && streamsRaw != nil {
		var streams []interface{}
		var streamSources []*structpb.Struct
		switch t := streamsRaw.(type) {
		case []interface{}:
			streams = t
			for _, value := range source.Fields[streamsKey].GetListValue().GetValues() {
				streamSources = append(streamSources, value.GetStructValue())
			}
		case map[string]interface{}:
			// a weakly typed decoder turns a single value into a slice of one, and an
			// empty map into an empty slice
			if len(t) > 0 {
				streams = []interface{}{t}
				streamSources = []*structpb.Struct{source.Fields[streamsKey].GetStructValue()}
			}
		default:
			return nil, decodeError(unexpectedTypeError("streams", "a slice", streamsRaw))
		}
		result.Streams = make([]*proto.Stream, 0, len(streams))
		for i, streamRaw := range streams {
			name := fmt.Sprintf("streams[%d]", i)
			streamMap, ok := streamRaw.(map[string]interface{})
			if !ok {
				return nil, decodeError(unexpectedTypeError(name, "a map or struct", streamRaw))
			}
			stream := &proto.Stream{Source: streamSources[i]}
			if stream.Id, err = stringField(streamMap, "id", name+"."); err != nil {
				return nil, decodeError(err)
			}
			if stream.DataStream, err = dataStreamField(streamMap, stream.Source, name+"."); err != nil {
				return nil, err
			}
			result.Streams = append(result.Streams, stream)
		}
	}

	return result, nil
}

func decodeError(err error) error {
	return fmt.Errorf("decoding error: %w", err)
}

func unexpectedTypeError(name string, expected string, got interface{}) error {
	kind := "nil"
	if got != nil {
		kind = reflect.TypeOf(got).Kind().String()
	}
	return fmt.Errorf("'%s' expected %s, got %q", name, expected, kind)
}

// lookupField returns the key and value of the field, matching the key exactly or, failing
// that, case-insensitively.
func lookupField(m map[string]interface{}, name string) (string, interface{}, bool) {
	if v, ok := m[name]; ok {
		return name, v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return k, v, true
		}
	}
	return "", nil, false
}

// stringValue converts a scalar value into a string the way a weakly typed decoder would. nil
// converts into the empty string. Non-scalar values are rejected.
func stringValue(v interface{}) (string, error) {
	switch t := v.(type) {
	case nil:
		return "", nil
	case string:
		return t, nil
	case bool:
		if t {
			return "1", nil
		}
		return "0", nil
	case []byte:
		return string(t), nil
	case json.Number:
		return string(t), nil
	}
	if f, ok := numberValue(v); ok {
		switch t := v.(type) {
		case float32, float64:
			return strconv.FormatFloat(f, 'f', -1, 64), nil
		case uint, uint8, uint16, uint32, uint64:
			return strconv.FormatUint(reflect.ValueOf(t).Uint(), 10), nil
		default:
			return strconv.FormatInt(reflect.ValueOf(t).Int(), 10), nil
		}
	}
	return "", fmt.Errorf("expected type 'string', got unconvertible type '%T'", v)
}

// stringField returns the field as a string, see stringValue. prefix is only used in error messages.
func stringField(m map[string]interface{}, name string, prefix string) (string, error) {
	_, v, ok := lookupField(m, name)
	if !ok {
		return "", nil
	}
	s, err := stringValue(v)
	if err != nil {
		return "", fmt.Errorf("'%s%s' %w", prefix, name, err)
	}
	return s, nil
}

// uint64Field returns the field as a uint64, converting values the way a weakly typed decoder
// would, except that negative values are rejected instead of wrapping around. prefix is only
// used in error messages.
func uint64Field(m map[string]interface{}, name string, prefix string) (uint64, error) {
	_, v, ok := lookupField(m, name)
	if !ok || v == nil {
		return 0, nil
	}
	switch t := v.(type) {
	case bool:
		if t {
			return 1, nil
		}
		return 0, nil
	case string:
		if t == "" {
			return 0, nil
		}
		u, err := strconv.ParseUint(t, 0, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse '%s%s' as uint: %w", prefix, name, err)
		}
		return u, nil
	case json.Number:
		u, err := strconv.ParseUint(string(t), 0, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse '%s%s' as uint: %w", prefix, name, err)
		}
		return u, nil
	}
	if f, ok := numberValue(v); ok {
		if f < 0 {
			return 0, fmt.Errorf("cannot parse '%s%s', %v overflows uint", prefix, name, v)
		}
		switch t := v.(type) {
		case uint, uint8, uint16, uint32, uint64:
			return reflect.ValueOf(t).Uint(), nil
		case float32, float64:
			return uint64(f), nil
		default:
			return uint64(reflect.ValueOf(t).Int()), nil //nolint:gosec // checked to be positive above
		}
	}
	return 0, fmt.Errorf("'%s%s' expected type 'uint64', got unconvertible type '%T'", prefix, name, v)
}

// numberValue returns the value as a float64 when it is a numeric type supported by structpb.
func numberValue(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int8:
		return float64(t), true
	case int16:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint:
		return float64(t), true
	case uint8:
		return float64(t), true
	case uint16:
		return float64(t), true
	case uint32:
		return float64(t), true
	case uint64:
		return float64(t), true
	case float32:
		return float64(t), true
	case float64:
		return t, true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}

// dataStreamField returns the proto.DataStream of the map: the nested data_stream dictionary,
// if any, merged with the flattened data_stream.<field> keys. source is the converted form of
// the map, prefix is only used in error messages.
func dataStreamField(m map[string]interface{}, source *structpb.Struct, prefix string) (*proto.DataStream, error) {
	ds := &proto.DataStream{}
	if key, dsRaw, ok := lookupField(m, "data_stream"); ok && dsRaw != nil {
		dsMap, ok := dsRaw.(map[string]interface{})
		if !ok {
			return nil, decodeError(unexpectedTypeError(prefix+"data_stream", "a map or struct", dsRaw))
		}
		ds.Source = source.Fields[key].GetStructValue()
		var err error
		if ds.Dataset, err = stringField(dsMap, "dataset", prefix+"data_stream."); err != nil {
			return nil, decodeError(err)
		}
		if ds.Type, err = stringField(dsMap, "type", prefix+"data_stream."); err != nil {
			return nil, decodeError(err)
		}
		if ds.Namespace, err = stringField(dsMap, "namespace", prefix+"data_stream."); err != nil {
			return nil, decodeError(err)
		}
	}
	ds, err := deDotDataStream(ds, m)
	if err != nil {
		return nil, fmt.Errorf("could not dedot '%sdata_stream': %w", prefix, err)
	}
	return ds, nil
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
		_, v, ok := lookupField(source, key)
		if !ok {
			continue
		}
		if *field, err = flattenedValue(v, key); err != nil {
			return tmp, err
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
