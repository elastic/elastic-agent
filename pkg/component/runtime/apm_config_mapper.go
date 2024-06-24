// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"sort"
	"strings"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
)

var zeroElasticAPMTLS = config.APMTLS{}

func MapAPMConfig(conf *config.APMConfig) *proto.APMConfig {
	if conf == nil {
		// component apm config is nil, so the protobuf config is nil as well
		return nil
	}

	elasticAPMConf := &proto.ElasticAPM{
		Environment:  conf.Environment,
		ApiKey:       conf.APIKey,
		SecretToken:  conf.SecretToken,
		Hosts:        conf.Hosts,
		GlobalLabels: buildGlobalLabelsString(conf.GlobalLabels),
	}

	if conf.TLS != zeroElasticAPMTLS {
		// we have some TLS config to propagate too
		elasticAPMConf.Tls = &proto.ElasticAPMTLS{
			SkipVerify: conf.TLS.SkipVerify,
			ServerCert: conf.TLS.ServerCertificate,
			ServerCa:   conf.TLS.ServerCA,
		}
	}

	return &proto.APMConfig{Elastic: elasticAPMConf}
}

func buildGlobalLabelsString(labels map[string]string) string {
	const separator = ","

	if len(labels) == 0 {
		return ""
	}

	//prepare sorted keys to make output deterministic
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	// create the key=value string
	buf := new(strings.Builder)
	for _, k := range keys {
		if buf.Len() > 0 {
			buf.WriteString(separator)
		}
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(labels[k])
	}
	return buf.String()
}
