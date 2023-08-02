package runtime

import (
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component"
)

var zeroElasticAPMTLS = config.APMTLS{}

func mapAPMConfig(conf *component.APMConfig) *proto.APMConfig {
	if conf == nil {
		// component apm config is nil, so the pb config is nil as well
		return nil
	}

	elasticAPMConf := &proto.ElasticAPM{
		Environment: conf.Elastic.Environment,
		APIKey:      &conf.Elastic.APIKey,
		SecretToken: &conf.Elastic.SecretToken,
		Hosts:       append([]string{}, conf.Elastic.Hosts...),
	}

	if conf.Elastic.TLS != zeroElasticAPMTLS {
		// we have some TLS config to propagate too
		elasticAPMConf.Tls = &proto.ElasticAPMTLS{
			SkipVerify: conf.Elastic.TLS.SkipVerify,
			ServerCert: conf.Elastic.TLS.ServerCertificate,
			ServerCa:   conf.Elastic.TLS.ServerCA,
		}
	}

	return &proto.APMConfig{Elastic: elasticAPMConf}
}
