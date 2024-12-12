// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package redact

import (
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/go-ucfg"
)

const (
	// REDACTED is used to replace sensitive fields
	REDACTED = "<REDACTED>"
)

// Redact redacts sensitive values from the passed mapStr.
func RedactSecrets(mapStr map[string]any, errOut io.Writer) map[string]any {
	return RedactPossibleSecrets(RedactSecretPaths(mapStr, errOut), errOut)
}

// RedactSecretPaths will check the passed mapStr input for a secret_paths attribute.
// If found it will replace the value for every key in the paths list with <REDACTED> and return the resulting map.
// Any issues or errors will be written to the errOut writer.
func RedactSecretPaths(mapStr map[string]any, errOut io.Writer) map[string]any {
	v, ok := mapStr["secret_paths"]
	if !ok {
		return mapStr
	}
	arr, ok := v.([]interface{})
	if !ok {
		fmt.Fprintln(errOut, "No output redaction: secret_paths attribute is not a list.")
		return mapStr
	}
	cfg := ucfg.MustNewFrom(mapStr)
	for _, v := range arr {
		key, ok := v.(string)
		if !ok {
			fmt.Fprintf(errOut, "No output redaction for %q: expected type string, is type %T.\n", v, v)
			continue
		}

		if ok, _ := cfg.Has(key, -1, ucfg.PathSep(".")); ok {
			err := cfg.SetString(key, -1, REDACTED, ucfg.PathSep("."))
			if err != nil {
				fmt.Fprintf(errOut, "No output redaction for %q: %v.\n", key, err)
			}
		}
	}
	result, err := config.MustNewConfigFrom(cfg).ToMapStr()
	if err != nil {
		return mapStr
	}
	return result
}

func RedactPossibleSecrets(mapStr map[string]any, errOut io.Writer) map[string]any {
	return redactMap(mapStr, errOut)
}

// redactMap redacts sensitive values from the inputMap
func redactMap[K comparable](inputMap map[K]interface{}, errOut io.Writer) map[K]interface{} {
	if inputMap == nil {
		return nil
	}
	for key, value := range inputMap {
		if value != nil {
			switch value.(type) {
			case string:
				if keyString, ok := any(key).(string); ok {
					if shouldRedact(keyString) {
						value = REDACTED
					}
				}
			default:
				redactAny(key, value, errOut)
			}
		}

		inputMap[key] = value
	}
	return inputMap
}

func redactAny(key, value any, errOut io.Writer) {
	if value == nil {
		return
	}
	switch inputType := value.(type) {
	case map[string]interface{}:
		value = redactMap(inputType, errOut)
	case map[interface{}]interface{}:
		value = redactMap(inputType, errOut)
	case map[int]interface{}:
		value = redactMap(inputType, errOut)
	case []any:
		value = redactSlice(key, inputType, errOut)
	default:
		// in cases where we got some weird kind of map we couldn't parse, print a warning
		if reflect.TypeOf(value).Kind() == reflect.Map {
			fmt.Fprintf(errOut, "[WARNING]: file may be partially redacted, could not cast value %v of type %T", key, value)
		}

	}
}

func redactSlice(key any, inputSlice []any, errOut io.Writer) []any {
	for i := range inputSlice {
		redactAny(fmt.Sprintf("%v[%d]", key, i), inputSlice[i], errOut)
	}
	return inputSlice
}

func shouldRedact(key string) bool {
	// "routekey" shouldn't be redacted.
	// Add any other exceptions here.
	if key == "routekey" {
		return false
	}

	key = strings.ToLower(key)
	return strings.Contains(key, "certificate") ||
		strings.Contains(key, "passphrase") ||
		strings.Contains(key, "password") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "key")
}
