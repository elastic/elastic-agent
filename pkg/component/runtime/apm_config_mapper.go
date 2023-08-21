package runtime

import (
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
)

var zeroElasticAPMTLS = config.APMTLS{}

func MapAPMConfig(conf *config.APMConfig) *proto.APMConfig {
	if conf == nil {
		// component apm config is nil, so the pb config is nil as well
		return nil
	}

	elasticAPMConf := &proto.ElasticAPM{
		Environment: conf.Environment,
		APIKey:      &conf.APIKey,
		SecretToken: &conf.SecretToken,
		Hosts:       append([]string{}, conf.Hosts...),
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
