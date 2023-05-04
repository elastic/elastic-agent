outputs:
  default:
    type: elasticsearch
    hosts: [{{ .Es.Host }}]
    username: "{{ .Es.User }}"
    password: "{{ .Es.Password }}"

inputs:
  - type: system/metrics
    id: {{.Id}}
    data_stream.namespace: default
    use_output: default
    streams:
      - metricset: cpu
        # Dataset name must conform to the naming conventions for Elasticsearch indices, cannot contain dashes (-), and cannot exceed 100 bytes
        data_stream.dataset: system.cpu
      - metricset: memory
        data_stream.dataset: system.memory
      - metricset: network
        data_stream.dataset: system.network
      - metricset: filesystem
        data_stream.dataset: system.filesystem
