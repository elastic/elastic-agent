// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"net/url"
	"reflect"
	"time"

	"github.com/go-viper/mapstructure/v2"

	"github.com/elastic/beats/v7/libbeat/common/transport/kerberos"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

// Helper function to conditionally add fields to the map
func setIfNotNil(m map[string]any, key string, value any) {
	if value == nil {
		return
	}

	v := reflect.ValueOf(value)

	switch v.Kind() {
	case reflect.Int:
		// we set integer values even if they are zero
		m[key] = value
	case reflect.Map, reflect.Slice:
		if v.Len() > 0 {
			m[key] = value
		}
	default:
		if !reflect.DeepEqual(value, reflect.Zero(reflect.TypeOf(value)).Interface()) {
			m[key] = value
		}
	}
}

// cfgDecodeHookFunc returns a mapstructure.DecodeHookFunc that handles custom decoding logic
func cfgDecodeHookFunc() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data any,
	) (any, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}

		switch {
		case t == reflect.TypeOf(time.Duration(5)):
			d, err := time.ParseDuration(data.(string))
			if err != nil {
				return d, fmt.Errorf("failed parsing duration: %w", err)
			} else {
				return d, nil
			}
		case t == reflect.TypeOf(tlscommon.TLSVerificationMode(0)):
			verificationMode := tlscommon.TLSVerificationMode(0)
			if err := verificationMode.Unpack(data); err != nil {
				return nil, fmt.Errorf("failed parsing TLS verification mode: %w", err)
			}
			return verificationMode, nil
		case t == reflect.TypeOf(httpcommon.ProxyURI(url.URL{})):
			proxyURL := httpcommon.ProxyURI(url.URL{})
			if err := proxyURL.Unpack(data.(string)); err != nil {
				return nil, fmt.Errorf("failed parsing proxy_url: %w", err)
			}
			return proxyURL, nil
		case t == reflect.TypeOf(kerberos.AuthType(0)):
			var authType kerberos.AuthType
			if err := authType.Unpack(data.(string)); err != nil {
				return nil, fmt.Errorf("failed parsing kerberos.auth_type: %w", err)
			}
			return authType, nil
		case t == reflect.TypeOf([]string{}):
			return []string{data.(string)}, nil
		case t == reflect.TypeOf([]tlscommon.CipherSuite{tlscommon.CipherSuite(0)}):
			cipherSuite := tlscommon.CipherSuite(0)
			if err := cipherSuite.Unpack(data); err != nil {
				return nil, fmt.Errorf("failed parsing ssl cipher_suites: %w", err)
			}
			return []tlscommon.CipherSuite{cipherSuite}, nil
		case t == reflect.TypeOf([]tlscommon.TLSVersion{tlscommon.TLSVersion(0)}):
			tlsVersion := tlscommon.TLSVersion(0)
			if err := tlsVersion.Unpack(data); err != nil {
				return nil, fmt.Errorf("failed parsing ssl supported_protocols: %w", err)
			}
			return []tlscommon.TLSVersion{tlsVersion}, nil
		case t == reflect.TypeOf([]tlscommon.TLSCurveType{tlscommon.TLSCurveType(0)}):
			tlsCurveType := tlscommon.TLSCurveType(0)
			if err := tlsCurveType.Unpack(data); err != nil {
				return nil, fmt.Errorf("failed parsing ssl curve_types: %w", err)
			}
			return []tlscommon.TLSCurveType{tlsCurveType}, nil
		default:
			return data, nil
		}
	}
}
