package runtime

import (
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
)

func TestMapAPMConfig(t *testing.T) {
	type args struct {
		conf *config.APMConfig
	}
	tests := []struct {
		name string
		args args
		want *proto.APMConfig
	}{
		{
			name: "nil config",
			args: args{
				conf: nil,
			},
			want: nil,
		},
		{
			name: "full config",
			args: args{
				conf: &config.APMConfig{
					Environment:  "environment",
					APIKey:       "apikey",
					SecretToken:  "secrettoken",
					Hosts:        []string{"host1", "host2"},
					GlobalLabels: map[string]string{"k1": "v1", "k2": "v2"},
					TLS: config.APMTLS{
						SkipVerify:        true,
						ServerCertificate: "servercertificate",
						ServerCA:          "serverca",
					},
				},
			},
			want: &proto.APMConfig{
				Elastic: &proto.ElasticAPM{
					Tls: &proto.ElasticAPMTLS{
						SkipVerify: true,
						ServerCert: "servercertificate",
						ServerCa:   "serverca",
					},
					Environment:  "environment",
					ApiKey:       "apikey",
					SecretToken:  "secrettoken",
					Hosts:        []string{"host1", "host2"},
					GlobalLabels: "k1=v1,k2=v2",
				},
			},
		},
		{
			name: "config without global labels",
			args: args{
				conf: &config.APMConfig{
					Environment:  "environment",
					APIKey:       "apikey",
					SecretToken:  "secrettoken",
					Hosts:        []string{"host1", "host2"},
					GlobalLabels: nil,
					TLS: config.APMTLS{
						SkipVerify:        true,
						ServerCertificate: "servercertificate",
						ServerCA:          "serverca",
					},
				},
			},
			want: &proto.APMConfig{
				Elastic: &proto.ElasticAPM{
					Tls: &proto.ElasticAPMTLS{
						SkipVerify: true,
						ServerCert: "servercertificate",
						ServerCa:   "serverca",
					},
					Environment:  "environment",
					ApiKey:       "apikey",
					SecretToken:  "secrettoken",
					Hosts:        []string{"host1", "host2"},
					GlobalLabels: "",
				},
			},
		},
		{
			name: "config without hosts",
			args: args{
				conf: &config.APMConfig{
					Environment:  "environment",
					APIKey:       "apikey",
					SecretToken:  "secrettoken",
					GlobalLabels: map[string]string{"k1": "v1", "k2": "v2"},
					TLS: config.APMTLS{
						SkipVerify:        true,
						ServerCertificate: "servercertificate",
						ServerCA:          "serverca",
					},
				},
			},
			want: &proto.APMConfig{
				Elastic: &proto.ElasticAPM{
					Tls: &proto.ElasticAPMTLS{
						SkipVerify: true,
						ServerCert: "servercertificate",
						ServerCa:   "serverca",
					},
					Environment:  "environment",
					ApiKey:       "apikey",
					SecretToken:  "secrettoken",
					Hosts:        nil,
					GlobalLabels: "k1=v1,k2=v2",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, MapAPMConfig(tt.args.conf), "MapAPMConfig(%v)", tt.args.conf)
		})
	}
}
