// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"go.opentelemetry.io/collector/config/configtls"

	"github.com/elastic/beats/v7/libbeat/common/transport/kerberos"
	"github.com/elastic/beats/v7/libbeat/publisher/queue/memqueue"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

var tlsVersions = map[uint16]string{
	tls.VersionTLS11: "1.1",
	tls.VersionTLS12: "1.2",
	tls.VersionTLS13: "1.3",
}

var otelCurveType = map[tls.CurveID]string{
	tls.CurveP256: "P256",
	tls.CurveP384: "P384",
	tls.CurveP521: "P521",
	tls.X25519:    "X25519",
}

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

func getQueueSize(logger *logp.Logger, output *config.C) int {
	size, err := output.Int("queue.mem.events", -1)
	if err != nil {
		logger.Debugf("Failed to get queue size: %v", err)
		return memqueue.DefaultEvents // return default queue.mem.events for sending_queue in case of an errr
	}
	return int(size)
}

func getFlushTimeout(logger *logp.Logger, output *config.C) string {
	timeout, err := output.String("queue.mem.flush.timeout", -1)
	if err != nil {
		logger.Debugf("Failed to get flush timeout: %v", err)
		return "10s" // return default queue.mem.flush.timeout for sending_queue in case of an errr
	}
	return timeout
}

// TLSCommonToOTel converts a tlscommon.Config into the OTel configtls.ClientConfig
// ca_trusted_fingerprint, ca_sha_256 and verification_mode: strict/certificate are not handled by this method
func TLSToOTel(tlsConfig *tlscommon.Config, logger *logp.Logger) (map[string]any, error) {
	logger = logger.Named("tls-to-otel")
	otelTLSConfig := map[string]any{}

	if tlsConfig == nil {
		return nil, nil
	}

	if !tlsConfig.IsEnabled() {
		return map[string]any{
			"insecure": true,
		}, nil
	}

	// validate the beats config before proceeding
	if err := tlsConfig.Validate(); err != nil {
		return nil, err
	}

	// handles verification_mode: none and full
	if tlsConfig.VerificationMode == tlscommon.VerifyNone {
		otelTLSConfig["insecure_skip_verify"] = true
	}

	// unpacks -> ssl.certificate_authorities
	// The OTel exporter accepts either single CA file or CA string. However,
	// Beats support any combination and number of files and certificates
	// as string, so we read them all and assemble one PEM string with
	// all CA certificates
	var caCerts []string
	for _, ca := range tlsConfig.CAs {
		d, err := tlscommon.ReadPEMFile(logger, ca, "")
		if err != nil {
			logger.Errorf("Failed reading CA: %+v", err)
			return nil, err
		}
		caCerts = append(caCerts, string(d))
	}

	var (
		certKeyPem string
		certPem    string
	)

	if tlsConfig.Certificate.Key != "" {
		// unpacks ->  ssl.key
		certKeyBytes, err := tlscommon.ReadPEMFile(logger, tlsConfig.Certificate.Key, tlsConfig.Certificate.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed reading key file: %w", err)
		}
		certKeyPem = string(certKeyBytes)

		// unpacks ->  ssl.certificate
		certBytes, err := tlscommon.ReadPEMFile(logger, tlsConfig.Certificate.Certificate, "")
		if err != nil {
			logger.Errorf("Failed reading cert file: %+v", err)
			return nil, fmt.Errorf("failed reading cert file: %w", err)
		}
		certPem = string(certBytes)
	}

	tlsCfg, err := tlscommon.LoadTLSConfig(tlsConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("cannot load SSL configuration: %w", err)
	}
	goTLSConfig := tlsCfg.ToConfig()

	// convert beats' cipher suits to OTel compatible format
	ciphersuites := []string{}
	for _, cs := range goTLSConfig.CipherSuites {
		ciphersuites = append(ciphersuites, tls.CipherSuiteName(cs))
	}

	// convert beat curve ID to OTel compatible curve preference
	curve_preferences := []string{}
	for _, cp := range goTLSConfig.CurvePreferences {
		curve_preferences = append(curve_preferences, otelCurveType[cp])
	}

	setIfNotNil(otelTLSConfig, "ca_pem", strings.Join(caCerts, "")) // ssl.certificate_authorities
	setIfNotNil(otelTLSConfig, "cert_pem", certPem)                 // ssl.certificate
	setIfNotNil(otelTLSConfig, "key_pem", certKeyPem)               // ssl.key
	setIfNotNil(otelTLSConfig, "cipher_suites", ciphersuites)       // ssl.cipher_suites
	setIfNotNil(otelTLSConfig, "curve_preferences", curve_preferences)

	otelTLSConfig["min_version"] = tlsVersions[goTLSConfig.MinVersion]
	otelTLSConfig["max_version"] = tlsVersions[goTLSConfig.MaxVersion]

	if err := typeSafetyCheck(otelTLSConfig); err != nil {
		return nil, err
	}
	return otelTLSConfig, nil
}

// For type safety check
func typeSafetyCheck(value map[string]any) error {
	// the returned valued should match `clienttls.Config` type.
	// it throws an error if non existing key names  are set
	var result configtls.ClientConfig
	d, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Squash:      true,
		Result:      &result,
		ErrorUnused: true,
	})

	err := d.Decode(value)
	if err != nil {
		return err
	}
	return err
}
