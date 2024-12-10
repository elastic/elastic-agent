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
	return redactMap(errOut, redactSecretPaths(mapStr, errOut))
}

// RedactSecretPaths will check the passed mapStr input for a secret_paths attribute.
// If found it will replace the value for every key in the paths list with <REDACTED> and return the resulting map.
// Any issues or errors will be written to the errOut writer.
func redactSecretPaths(mapStr map[string]any, errOut io.Writer) map[string]any {
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

// redactMap redacts sensitive values from the inputMap
func redactMap[K comparable](errOut io.Writer, inputMap map[K]interface{}) map[K]interface{} {
	if inputMap == nil {
		return nil
	}
	for rootKey, rootValue := range inputMap {
		if rootValue != nil {
			switch cast := rootValue.(type) {
			case map[string]interface{}:
				rootValue = redactMap(errOut, cast)
			case map[interface{}]interface{}:
				rootValue = redactMap(errOut, cast)
			case map[int]interface{}:
				rootValue = redactMap(errOut, cast)
			case string:
				if keyString, ok := any(rootKey).(string); ok {
					if redactKey(keyString) {
						rootValue = REDACTED
					}
				}
			default:
				// in cases where we got some weird kind of map we couldn't parse, print a warning
				if reflect.TypeOf(rootValue).Kind() == reflect.Map {
					fmt.Fprintf(errOut, "[WARNING]: file may be partly redacted, could not cast value %v of type %T", rootKey, rootValue)
				}

			}
		}

		inputMap[rootKey] = rootValue

	}
	return inputMap
}

func redactKey(k string) bool {
	// "routekey" shouldn't be redacted.
	// Add any other exceptions here.
	if k == "routekey" {
		return false
	}

	k = strings.ToLower(k)
	return strings.Contains(k, "certificate") ||
		strings.Contains(k, "passphrase") ||
		strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "key")
}
