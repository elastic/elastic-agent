// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleetservertest

import (
	"fmt"
	"strings"
	"text/template"
)

type TmplData struct {
	AckToken   string
	AgentID    string
	ActionID   string
	PolicyID   string
	FleetHosts string
	SourceURI  string
	CreatedAt  string
	Output     struct {
		APIKey string
		Hosts  string
		Type   string
	}
}

func NewCheckinResponse(actions string) string {
	return fmt.Sprintf(checkinResponseJSONFakeComponentTmpl, actions)
}

func NewActionPolicyChangeWithFakeComponent(data TmplData) (string, error) {
	t := template.Must(template.New("actionPolicyChangeTmpl").
		Parse(actionPolicyChangeTmpl))

	buf := &strings.Builder{}
	err := t.Execute(buf, data)
	if err != nil {
		return "", fmt.Errorf("failed building action: %w", err)
	}

	return buf.String(), nil
}

const (
	checkinResponseJSONFakeComponentTmpl = `
{
  "ack_token": "{{.AckToken}}",
  "action": "checkin",
  "actions": %s
}`

	actionPolicyChangeTmpl = `
    [{
      "agent_id": "{{.AgentID}}",
      "created_at": "2023-05-31T11:37:50.607Z",
      "data": {
        "policy": {
          "agent": {
            "download": {
              "sourceURI": "{{.SourceURI}}"
            },
            "monitoring": {
              "namespace": "default",
              "use_output": "default",
              "enabled": true,
              "logs": true,
              "metrics": true
            },
            "features": {},
            "protection": {
              "enabled": false,
              "uninstall_token_hash": "lORSaDIQq4nglUMJwWjKrwexj4IDRJA+FtoQeeqKH/I=",
              "signing_key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ9BPoHUCyLyElVpfwvKeFdUt6U9wBb+QlZNf4cy5eAwK9Xh4D8fClgciPeRs3j62i6IEeGyvOs9U3+fElyUigg=="
            }
          },
          "fleet": {
            "hosts": [{{.FleetHosts}}]
          },
          "id": "{{.ActionID}}",
          "inputs": [
            {
              "id": "fake-input",
              "revision": 1,
              "name": "fake-input",
              "type": "fake-input",
              "data_stream": {
                "namespace": "default"
              },
              "use_output": "default",
              "package_policy_id": "{{.PolicyID}}",
              "streams": [],
              "meta": {
                "package": {
                  "name": "fake-input",
                  "version": "0.0.1"
                }
              }
            }
          ],
          "output_permissions": {
            "default": {}
          },
          "outputs": {
            "default": {
              "api_key": "{{.Output.APIKey}}",
              "hosts": [{{.Output.Hosts}}],
              "type": "{{.Output.Type}}"
            }
          },
          "revision": 2,
          "secret_references": [],
          "signed": {
            "data": "eyJpZCI6IjI0ZTRkMDMwLWZmYTctMTFlZC1iMDQwLTlkZWJhYTVmZWNiOCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6ZmFsc2UsInVuaW5zdGFsbF90b2tlbl9oYXNoIjoibE9SU2FESVFxNG5nbFVNSndXaktyd2V4ajRJRFJKQStGdG9RZWVxS0gvST0iLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVE5QlBvSFVDeUx5RWxWcGZ3dktlRmRVdDZVOXdCYitRbFpOZjRjeTVlQXdLOVhoNEQ4ZkNsZ2NpUGVSczNqNjJpNklFZUd5dk9zOVUzK2ZFbHlVaWdnPT0ifX19",
            "signature": "MEUCIQCfS6wPj/AvfFA79dwKATnvyFl/ZeyA8eKOLHg1XuA9NgIgNdhjIT+G/GZFqsVoWk5jThONhpqPhfiHLE5OkTdrwT0="
          }
        }
      },
      "id": "{{.ActionID}}",
      "input_type": "",
      "type": "POLICY_CHANGE"
    }]`

	checkinResponseJSONPolicySystemIntegration = `{"ack_token":"%s","action":"checkin","actions":[{"agent_id":"%s","created_at":"2023-05-31T11:37:50.607Z","data":{"policy":{"agent":{"download":{"sourceURI":"https://artifacts.elastic.co/downloads/"},"monitoring":{"namespace":"default","use_output":"default","enabled":true,"logs":true,"metrics":true},"features":{},"protection":{"enabled":false,"uninstall_token_hash":"lORSaDIQq4nglUMJwWjKrwexj4IDRJA+FtoQeeqKH/I=","signing_key":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ9BPoHUCyLyElVpfwvKeFdUt6U9wBb+QlZNf4cy5eAwK9Xh4D8fClgciPeRs3j62i6IEeGyvOs9U3+fElyUigg=="}},"fleet":{"hosts":["https://039f8e82bf51414bb159b622ca02b284.fleet.us-central1.gcp.qa.cld.elstc.co:443"]},"id":"24e4d030-ffa7-11ed-b040-9debaa5fecb8","inputs":[{"id":"logfile-system-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","revision":1,"name":"system-1","type":"logfile","data_stream":{"namespace":"default"},"use_output":"default","package_policy_id":"bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","streams":[{"id":"logfile-system.auth-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"logs","dataset":"system.auth"},"ignore_older":"72h","paths":["/var/log/auth.log*","/var/log/secure*"],"exclude_files":[".gz$"],"multiline":{"pattern":"^\\s","match":"after"},"tags":["system-auth"],"processors":[{"add_locale":null}]},{"id":"logfile-system.syslog-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"logs","dataset":"system.syslog"},"paths":["/var/log/messages*","/var/log/syslog*","/var/log/system*"],"exclude_files":[".gz$"],"multiline":{"pattern":"^\\s","match":"after"},"processors":[{"add_locale":null}],"ignore_older":"72h"}],"meta":{"package":{"name":"system","version":"1.29.0"}}},{"id":"winlog-system-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","revision":1,"name":"system-1","type":"winlog","data_stream":{"namespace":"default"},"use_output":"default","package_policy_id":"bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","streams":[{"id":"winlog-system.application-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"logs","dataset":"system.application"},"name":"Application","condition":"${host.platform} == 'windows'","ignore_older":"72h"},{"id":"winlog-system.security-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"logs","dataset":"system.security"},"name":"Security","condition":"${host.platform} == 'windows'","ignore_older":"72h"},{"id":"winlog-system.system-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"logs","dataset":"system.system"},"name":"System","condition":"${host.platform} == 'windows'","ignore_older":"72h"}],"meta":{"package":{"name":"system","version":"1.29.0"}}},{"id":"system/metrics-system-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","revision":1,"name":"system-1","type":"system/metrics","data_stream":{"namespace":"default"},"use_output":"default","package_policy_id":"bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","streams":[{"id":"system/metrics-system.cpu-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.cpu"},"metricsets":["cpu"],"cpu.metrics":["percentages","normalized_percentages"],"period":"10s"},{"id":"system/metrics-system.diskio-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.diskio"},"metricsets":["diskio"],"diskio.include_devices":null,"period":"10s"},{"id":"system/metrics-system.filesystem-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.filesystem"},"metricsets":["filesystem"],"period":"1m","processors":[{"drop_event.when.regexp":{"system.filesystem.mount_point":"^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"}}]},{"id":"system/metrics-system.fsstat-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.fsstat"},"metricsets":["fsstat"],"period":"1m","processors":[{"drop_event.when.regexp":{"system.fsstat.mount_point":"^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)"}}]},{"id":"system/metrics-system.load-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.load"},"metricsets":["load"],"condition":"${host.platform} != 'windows'","period":"10s"},{"id":"system/metrics-system.memory-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.memory"},"metricsets":["memory"],"period":"10s"},{"id":"system/metrics-system.network-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.network"},"metricsets":["network"],"period":"10s","network.interfaces":null},{"id":"system/metrics-system.process-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.process"},"metricsets":["process"],"period":"10s","process.include_top_n.by_cpu":5,"process.include_top_n.by_memory":5,"process.cmdline.cache.enabled":true,"process.cgroups.enabled":false,"process.include_cpu_ticks":false,"processes":[".*"]},{"id":"system/metrics-system.process.summary-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.process.summary"},"metricsets":["process_summary"],"period":"10s"},{"id":"system/metrics-system.socket_summary-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.socket_summary"},"metricsets":["socket_summary"],"period":"10s"},{"id":"system/metrics-system.uptime-bedf2f42-a252-40bb-ab2b-8a7e1b874c7a","data_stream":{"type":"metrics","dataset":"system.uptime"},"metricsets":["uptime"],"period":"10s"}],"meta":{"package":{"name":"system","version":"1.29.0"}}}],"output_permissions":{"default":{"_elastic_agent_monitoring":{"indices":[{"names":["logs-elastic_agent.apm_server-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.apm_server-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.auditbeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.auditbeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.cloud_defend-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.cloudbeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.cloudbeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.elastic_agent-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.endpoint_security-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.endpoint_security-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.filebeat_input-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.filebeat_input-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.filebeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.filebeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.fleet_server-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.fleet_server-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.heartbeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.heartbeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.metricbeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.metricbeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.osquerybeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.osquerybeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-elastic_agent.packetbeat-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-elastic_agent.packetbeat-default"],"privileges":["auto_configure","create_doc"]}]},"_elastic_agent_checks":{"cluster":["monitor"]},"bedf2f42-a252-40bb-ab2b-8a7e1b874c7a":{"indices":[{"names":["logs-system.auth-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-system.syslog-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-system.application-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-system.security-default"],"privileges":["auto_configure","create_doc"]},{"names":["logs-system.system-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.cpu-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.diskio-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.filesystem-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.fsstat-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.load-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.memory-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.network-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.process-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.process.summary-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.socket_summary-default"],"privileges":["auto_configure","create_doc"]},{"names":["metrics-system.uptime-default"],"privileges":["auto_configure","create_doc"]}]}}},"outputs":{"default":{"api_key":"9fGrcYgBX6JHv-JteDYm:fErCEKVWQhuZedzb5ldYOQ","hosts":["https://743815b87bcf40e0b093b28ab0e131bb.us-central1.gcp.qa.cld.elstc.co:443"],"type":"elasticsearch"}},"revision":2,"secret_references":[],"signed":{"data":"eyJpZCI6IjI0ZTRkMDMwLWZmYTctMTFlZC1iMDQwLTlkZWJhYTVmZWNiOCIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6ZmFsc2UsInVuaW5zdGFsbF90b2tlbl9oYXNoIjoibE9SU2FESVFxNG5nbFVNSndXaktyd2V4ajRJRFJKQStGdG9RZWVxS0gvST0iLCJzaWduaW5nX2tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVE5QlBvSFVDeUx5RWxWcGZ3dktlRmRVdDZVOXdCYitRbFpOZjRjeTVlQXdLOVhoNEQ4ZkNsZ2NpUGVSczNqNjJpNklFZUd5dk9zOVUzK2ZFbHlVaWdnPT0ifX19","signature":"MEUCIQCfS6wPj/AvfFA79dwKATnvyFl/ZeyA8eKOLHg1XuA9NgIgNdhjIT+G/GZFqsVoWk5jThONhpqPhfiHLE5OkTdrwT0="}}},"id":"policy:24e4d030-ffa7-11ed-b040-9debaa5fecb8:2:1","input_type":"","type":"POLICY_CHANGE"}]}`
)
