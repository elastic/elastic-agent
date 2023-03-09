// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package component

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
)

const (
	sourceFieldName = "source"
)

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

	return result, nil
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
