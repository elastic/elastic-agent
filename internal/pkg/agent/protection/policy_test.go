// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package protection

import (
	"encoding/base64"
	"testing"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func getLogger() *logger.Logger {
	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.DebugLevel
	l, _ := logger.NewFromConfig("", loggerCfg, false)
	return l
}

func TestValidatePolicy4RealSignature(t *testing.T) {
	policy4Real := map[string]interface{}{"agent": map[string]interface{}{"download": map[string]interface{}{"sourceURI": "https://artifacts.elastic.co/downloads/"}, "features": map[string]interface{}{}, "monitoring": map[string]interface{}{"enabled": true, "logs": true, "metrics": true, "namespace": "default", "use_output": "default"}, "protection": map[string]interface{}{"enabled": true, "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqrEVMJBfAiW7Mz9ZHegwlB7n4deTASUa5LlJlDfuz0hxo/7WPc7gkVB5H8LgnObPfihgzML7rLsHPreWZTB10A==", "uninstall_token_hash": ""}}, "fleet": map[string]interface{}{"hosts": []interface{}{"https://12625d8400fc4955bf4c6047bd77f5eb.fleet.us-central1.gcp.foundit.no:443"}}, "id": "681b1230-b798-11ed-8be1-47153ce217a7", "inputs": []interface{}{map[string]interface{}{"data_stream": map[string]interface{}{"namespace": "default"}, "id": "logfile-system-beb724f7-1f11-46aa-8859-dc979f1ca30b", "meta": map[string]interface{}{"package": map[string]interface{}{"name": "system", "version": "1.24.3"}}, "name": "system-1", "package_policy_id": "beb724f7-1f11-46aa-8859-dc979f1ca30b", "revision": 1, "streams": []interface{}{map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.auth", "type": "logs"}, "exclude_files": []interface{}{".gz$"}, "id": "logfile-system.auth-beb724f7-1f11-46aa-8859-dc979f1ca30b", "ignore_older": "72h", "multiline": map[string]interface{}{"match": "after", "pattern": "^\\s"}, "paths": []interface{}{"/var/log/auth.log*", "/var/log/secure*"}, "processors": []interface{}{map[string]interface{}{"add_locale": interface{}(nil)}}, "tags": []interface{}{"system-auth"}}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.syslog", "type": "logs"}, "exclude_files": []interface{}{".gz$"}, "id": "logfile-system.syslog-beb724f7-1f11-46aa-8859-dc979f1ca30b", "ignore_older": "72h", "multiline": map[string]interface{}{"match": "after", "pattern": "^\\s"}, "paths": []interface{}{"/var/log/messages*", "/var/log/syslog*"}, "processors": []interface{}{map[string]interface{}{"add_locale": interface{}(nil)}}}}, "type": "logfile", "use_output": "default"}, map[string]interface{}{"data_stream": map[string]interface{}{"namespace": "default"}, "id": "winlog-system-beb724f7-1f11-46aa-8859-dc979f1ca30b", "meta": map[string]interface{}{"package": map[string]interface{}{"name": "system", "version": "1.24.3"}}, "name": "system-1", "package_policy_id": "beb724f7-1f11-46aa-8859-dc979f1ca30b", "revision": 1, "streams": []interface{}{map[string]interface{}{"condition": "${host.platform} == 'windows'", "data_stream": map[string]interface{}{"dataset": "system.application", "type": "logs"}, "id": "winlog-system.application-beb724f7-1f11-46aa-8859-dc979f1ca30b", "ignore_older": "72h", "name": "Application"}, map[string]interface{}{"condition": "${host.platform} == 'windows'", "data_stream": map[string]interface{}{"dataset": "system.security", "type": "logs"}, "id": "winlog-system.security-beb724f7-1f11-46aa-8859-dc979f1ca30b", "ignore_older": "72h", "name": "Security"}, map[string]interface{}{"condition": "${host.platform} == 'windows'", "data_stream": map[string]interface{}{"dataset": "system.system", "type": "logs"}, "id": "winlog-system.system-beb724f7-1f11-46aa-8859-dc979f1ca30b", "ignore_older": "72h", "name": "System"}}, "type": "winlog", "use_output": "default"}, map[string]interface{}{"data_stream": map[string]interface{}{"namespace": "default"}, "id": "system/metrics-system-beb724f7-1f11-46aa-8859-dc979f1ca30b", "meta": map[string]interface{}{"package": map[string]interface{}{"name": "system", "version": "1.24.3"}}, "name": "system-1", "package_policy_id": "beb724f7-1f11-46aa-8859-dc979f1ca30b", "revision": 1, "streams": []interface{}{map[string]interface{}{"cpu.metrics": []interface{}{"percentages", "normalized_percentages"}, "data_stream": map[string]interface{}{"dataset": "system.cpu", "type": "metrics"}, "id": "system/metrics-system.cpu-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"cpu"}, "period": "10s"}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.diskio", "type": "metrics"}, "diskio.include_devices": interface{}(nil), "id": "system/metrics-system.diskio-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"diskio"}, "period": "10s"}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.filesystem", "type": "metrics"}, "id": "system/metrics-system.filesystem-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"filesystem"}, "period": "1m", "processors": []interface{}{map[string]interface{}{"drop_event.when.regexp": map[string]interface{}{"system.filesystem.mount_point": "^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"}}}}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.fsstat", "type": "metrics"}, "id": "system/metrics-system.fsstat-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"fsstat"}, "period": "1m", "processors": []interface{}{map[string]interface{}{"drop_event.when.regexp": map[string]interface{}{"system.fsstat.mount_point": "^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"}}}}, map[string]interface{}{"condition": "${host.platform} != 'windows'", "data_stream": map[string]interface{}{"dataset": "system.load", "type": "metrics"}, "id": "system/metrics-system.load-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"load"}, "period": "10s"}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.memory", "type": "metrics"}, "id": "system/metrics-system.memory-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"memory"}, "period": "10s"}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.network", "type": "metrics"}, "id": "system/metrics-system.network-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"network"}, "network.interfaces": interface{}(nil), "period": "10s"}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.process", "type": "metrics"}, "id": "system/metrics-system.process-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"process"}, "period": "10s", "process.cgroups.enabled": false, "process.cmdline.cache.enabled": true, "process.include_cpu_ticks": false, "process.include_top_n.by_cpu": 5, "process.include_top_n.by_memory": 5, "processes": []interface{}{".*"}}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.process.summary", "type": "metrics"}, "id": "system/metrics-system.process.summary-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"process_summary"}, "period": "10s"}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.socket_summary", "type": "metrics"}, "id": "system/metrics-system.socket_summary-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"socket_summary"}, "period": "10s"}, map[string]interface{}{"data_stream": map[string]interface{}{"dataset": "system.uptime", "type": "metrics"}, "id": "system/metrics-system.uptime-beb724f7-1f11-46aa-8859-dc979f1ca30b", "metricsets": []interface{}{"uptime"}, "period": "10s"}}, "type": "system/metrics", "use_output": "default"}}, "output_permissions": map[string]interface{}{"default": map[string]interface{}{"_elastic_agent_checks": map[string]interface{}{"cluster": []interface{}{"monitor"}}, "_elastic_agent_monitoring": map[string]interface{}{"indices": []interface{}{map[string]interface{}{"names": []interface{}{"logs-elastic_agent.apm_server-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.apm_server-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.auditbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.auditbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.cloudbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.cloudbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.elastic_agent-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.endpoint_security-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.endpoint_security-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.filebeat_input-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.filebeat_input-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.filebeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.filebeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.fleet_server-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.fleet_server-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.heartbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.heartbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.metricbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.metricbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.osquerybeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.osquerybeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-elastic_agent.packetbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-elastic_agent.packetbeat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}}}, "beb724f7-1f11-46aa-8859-dc979f1ca30b": map[string]interface{}{"indices": []interface{}{map[string]interface{}{"names": []interface{}{"logs-system.auth-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-system.syslog-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-system.application-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-system.security-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"logs-system.system-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.cpu-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.diskio-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.filesystem-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.fsstat-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.load-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.memory-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.network-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.process-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.process.summary-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.socket_summary-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}, map[string]interface{}{"names": []interface{}{"metrics-system.uptime-default"}, "privileges": []interface{}{"auto_configure", "create_doc"}}}}}}, "outputs": map[string]interface{}{"default": map[string]interface{}{"api_key": "P-hbmYYBcCpUDgccekIT:e9LI7ZBtR_ivXNrw6LogkQ", "hosts": []interface{}{"https://9fde87b047954338b333360dfbd080d3.us-central1.gcp.foundit.no:443"}, "type": "elasticsearch"}}, "revision": 1, "signed": map[string]interface{}{"data": "eyJpZCI6IjY4MWIxMjMwLWI3OTgtMTFlZC04YmUxLTQ3MTUzY2UyMTdhNyIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6dHJ1ZSwidW5pbnN0YWxsX3Rva2VuX2hhc2giOiIiLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXFyRVZNSkJmQWlXN016OVpIZWd3bEI3bjRkZVRBU1VhNUxsSmxEZnV6MGh4by83V1BjN2drVkI1SDhMZ25PYlBmaWhnek1MN3JMc0hQcmVXWlRCMTBBPT0ifX19", "signature": "MEUCIQCdtCiVPHRUvvND5Btw7uuiXDku5ljWECEUnyYAQwMkSwIgM9cxkRjW56L7kG1fKH8t5zZeK7R02TKN8IsxgPZdWrs="}}

	policy, signatureValidationKey, err := ValidatePolicySignature(getLogger(), policy4Real, nil)
	diff := cmp.Diff(policy, policy4Real)
	if diff != "" {
		t.Fatal(diff)
	}

	diff = cmp.Diff("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqrEVMJBfAiW7Mz9ZHegwlB7n4deTASUa5LlJlDfuz0hxo/7WPc7gkVB5H8LgnObPfihgzML7rLsHPreWZTB10A==", base64.StdEncoding.EncodeToString(signatureValidationKey))
	if diff != "" {
		t.Fatal(diff)
	}
	diff = cmp.Diff(nil, err, cmpopts.EquateErrors())
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestGetAgentProtectionConfig(t *testing.T) {
	tests := []struct {
		name    string
		policy  map[string]interface{}
		wantCfg Config
		wantErr error
	}{
		{
			name:    "nil policy",
			wantErr: ErrNotFound,
		},
		{
			name:    "empty policy",
			policy:  map[string]interface{}{},
			wantErr: ErrNotFound,
		},
		{
			name:    "no agent protection policy",
			policy:  map[string]interface{}{"agent": map[string]interface{}{"download": map[string]interface{}{"sourceURI": "https://artifacts.elastic.co/downloads/"}}, "fleet": map[string]interface{}{"hosts": []interface{}{"https://d827a7a3c2064e1582f87d29384d9c79.fleet.us-west2.gcp.elastic-cloud.com:443"}}},
			wantErr: ErrNotFound,
		},
		{
			name:   "valid agent protection policy",
			policy: map[string]interface{}{"agent": map[string]interface{}{"download": map[string]interface{}{"sourceURI": "https://artifacts.elastic.co/downloads/"}, "protection": map[string]interface{}{"enabled": true, "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErokrJiDUkqBr9lmNl3c17/4mMDDXC/5yoZL96pSquKz90gaIYr7fF/cjiZrqujoCRvjPuEB87o9L78jjHRzP7g==", "uninstall_token_hash": "ABCD"}}, "fleet": map[string]interface{}{"hosts": []interface{}{"https://d827a7a3c2064e1582f87d29384d9c79.fleet.us-west2.gcp.elastic-cloud.com:443"}}},
			wantCfg: Config{
				Enabled: true,
				SignatureValidationKey: func() []byte {
					b, err := base64.StdEncoding.DecodeString("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErokrJiDUkqBr9lmNl3c17/4mMDDXC/5yoZL96pSquKz90gaIYr7fF/cjiZrqujoCRvjPuEB87o9L78jjHRzP7g==")
					if err != nil {
						t.Fatal(err)
					}
					return b
				}(),
				UninstallTokenHash: "ABCD",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := GetAgentProtectionConfig(tc.policy)
			diff := cmp.Diff(tc.wantCfg, cfg)
			if diff != "" {
				t.Fatal(diff)
			}
			diff = cmp.Diff(tc.wantErr, err, cmpopts.EquateErrors())
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
