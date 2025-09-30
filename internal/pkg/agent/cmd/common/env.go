// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package common

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func EnvWithDefault(def string, keys ...string) string {
	for _, key := range keys {
		val, ok := os.LookupEnv(key)
		if ok {
			return val
		}
	}
	return def
}

func EnvBool(keys ...string) bool {
	for _, key := range keys {
		val, ok := os.LookupEnv(key)
		if ok && isTrue(val) {
			return true
		}
	}
	return false
}

func EnvDurationWithDefault(defVal string, keys ...string) (time.Duration, error) {
	valStr := defVal
	for _, key := range keys {
		val, ok := os.LookupEnv(key)
		if ok {
			valStr = val
			break
		}
	}

	return time.ParseDuration(valStr)
}

func EnvIntWithDefault(defVal string, keys ...string) (int, error) {
	valStr := defVal
	for _, key := range keys {
		val, ok := os.LookupEnv(key)
		if ok {
			valStr = val
			break
		}
	}

	return strconv.Atoi(valStr)
}

func EnvTimeout(keys ...string) time.Duration {
	for _, key := range keys {
		val, ok := os.LookupEnv(key)
		if ok {
			dur, err := time.ParseDuration(val)
			if err == nil {
				return dur
			}
		}
	}
	return 0
}

func EnvMap(key string) map[string]string {
	m := make(map[string]string)
	prefix := key + "="
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, prefix) {
			continue
		}

		envVal := strings.TrimPrefix(env, prefix)

		keyValue := strings.SplitN(envVal, "=", 2)
		if len(keyValue) != 2 {
			continue
		}

		m[keyValue[0]] = keyValue[1]
	}

	return m
}

func isTrue(val string) bool {
	trueVals := []string{"1", "true", "yes", "y"}
	val = strings.ToLower(val)
	for _, v := range trueVals {
		if val == v {
			return true
		}
	}
	return false
}
