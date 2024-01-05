# How Agent CPU metrics in Fleet are calculated

## Journey

```mermaid
flowchart TD
    K[Fleet UI] -- reads from --> E[Elasticsearch]
    M[Metricbeat `http/json` metricset] -- writes to --> E
    M -- reads from --> A[Agent `/stats` endpoint]
    M -- reads from --> B[*Beat `/stats` endpoint]
    A -- reads from --> L1[`elastic-agent-system-metrics` report.SetupMetrics]
    L1 -- reads from --> H[Host system]
    B -- reads from --> L2[`elastic-agent-system-metrics` report.SetupMetrics]
    L2 -- reads from --> H[Host system]
```

### Fleet UI reading from Elasticsearch

The Fleet UI code makes the following query to the `metrics-elastic_agent.*` indices in Elasticsearch.  Only CPU-related
aggregations are shown; memory-related aggregations are omitted.

```json
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {
          "terms": {
            "_tier": [ "data_hot" ]
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-5m"
            }
          }
        },
        {
          "terms": {
            "elastic_agent.id": [ agentIds ]
          }
        },
        {
          "bool": {
            "filter": [
              {
                "bool": {
                  "should": [
                    {
                      "term": {
                        "data_stream.dataset": "elastic_agent.elastic_agent"
                      }
                    }
                  ]
                }
              }
            ]
          }
        }
      ]
    }
  },
  "aggs": {
    "agents": {
      "terms": {
        "field": "elastic_agent.id",
        "size": 1000
      },
      "aggs": {
        "sum_cpu": {
          "sum_bucket": {
            "buckets_path": "processes>avg_cpu"
          }
        },
        "processes": {
          "terms": {
            "field": "elastic_agent.process",
            "size": 1000,
            "order": {
              "_count": "desc"
            }
          },
          "aggs": {
            "avg_cpu": {
              "avg_bucket": {
                "buckets_path": "cpu_time_series>cpu"
              }
            },
            "cpu_time_series": {
              "date_histogram": {
                "field": "@timestamp",
                "calendar_interval": "minute"
              },
              "aggs": {
                "max_cpu": {
                  "max": {
                    "field": "system.process.cpu.total.value"
                  }
                },
                "cpu_derivative": {
                  "derivative": {
                    "buckets_path": "max_cpu",
                    "gap_policy": "skip",
                    "unit": "10s"
                  }
                },
                "cpu": {
                  "bucket_script": {
                    "buckets_path": {
                      "cpu_total": "cpu_derivative[normalized_value]"
                    },
                    "script": {
                      "source": "if (params.cpu_total > 0) { return params.cpu_total / params._interval }",
                      "lang": "painless",
                      "params": {
                        "_interval": 10000
                      }
                    },
                    "gap_policy": "skip"
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

### Metricbeat collects CPU metrics for Agent and the Beats it manages

There is one input in particular in the Agent policy that ultimately generates the data for the above ES query made by
the Fleet UI. This input is of type `http/metrics`, use the `monitoring` output, and has `id` = `metrics-monitoring-agent`.
A Metricbeat process is spawned for this input.

There are multiple inputs in the Metricbeat configuration that generate the data for the ES query.
  * One input is for generating data for the Agent itself. This input will have `namespace` = `agent` and
    `id` = `metrics-monitoring-agent`.
  * The remaining inputs will generate data for the various Beats managed by Agent. The number of inputs depends on the
    number of Beats. These inputs will have `namespace` = `agent` and `id` = `metrics-monitoring-*beat-$n`, where `$n`
    is the 1-based index of the Beat.

All these inputs run the `http` Metricbeat module, `json` metricset, and poll `$hostname/stats` endpoint every minute,
where `$hostname` is either the TCP address or unix socket path of the Agent's HTTP API or the Beats' HTTP APIs. Each
input has a `copy_fields` processor that copies the value of the `http.agent.beat.cpu` field to the `system.process.cpu` field.

Since the ES query aggregates on the `system.process.cpu.total.value` field, the corresponding field in the
`$hostname/stats` API response that we're interested in is `.beat.cpu.total.value`. The `.beat.cpu.total.value` returns
a counter value representing the total (user-space + kernel-space) duration, in milliseconds, spent by the Agent or Beat
utilizing the CPU since the process was started. More on how this duration is calculated in the next section.

### Agent and Beats collect CPU metrics using `elastic-agent-system-metrics`

At startup, both Agent and Beats call the [`SetupMetrics` function](https://github.com/elastic/elastic-agent-system-metrics/blob/085e4529f3c4f91dd377cadbbe7a2bf321989438/report/setup.go#L49)
from the `github.com/elastic/elastic-agent-system-metrics/report` package.  This function registers a function with the
monitoring registry. Whenever this function is called, it calculates and reports CPU and other metrics for the process in
question.  The calculation of CPU (and other) metrics depends on the OS the Agent or Beat process is running on.

#### Linux

On Linux, CPU metrics are collected by [reading the `/proc/$PID/stat` file](https://github.com/elastic/elastic-agent-system-metrics/blob/085e4529f3c4f91dd377cadbbe7a2bf321989438/metric/system/process/process_linux_common.go#L351).
This file contains whitespace-delimited values (fields) for various process metrics and other information. The field at
index 13 (0-based indexing) is the number of CPU ticks utilized by the process in user-space since it was started. The
field at index 14 is the number of CPU ticks utilized by the process in kernel-space since it was started.  As such, both
fields contain counter metrics. Both fields show the total number of CPU ticks consumed by the process across all available
cores (as opposed to showing normalized, per-core, values; [proof](https://gist.github.com/ycombinator/d55d884ec979fb86360a00b57f807de3)).

We want to convert these tick values into milliseconds so it becomes easier to figure out what percentage of CPU was
utilized by the process over a given period of time.  For example, if the process utilized 120 milliseconds of CPU time
over a period of 5 minutes, that would be a CPU utilization of 120 / (5 * 60 * 1000) = 0.0004 = 0.04%.

On a typical Linux host, there are 100 ticks per second. The actual value can be checked by running `getconf CLK_TCK`.
Therefore, if a process utilized T ticks, say in user-space, we can say that the process utilized (T / 100) seconds of
CPU time == (T / 100) * 1000 milliseconds of CPU time. We do this [conversion](https://github.com/elastic/elastic-agent-system-metrics/blob/085e4529f3c4f91dd377cadbbe7a2bf321989438/metric/system/process/process_linux_common.go#L374-L375)
from ticks to milliseconds for both user-space and kernel-space CPU utilization.

Finally, we [sum up](https://github.com/elastic/elastic-agent-system-metrics/blob/085e4529f3c4f91dd377cadbbe7a2bf321989438/metric/system/process/process_linux_common.go#L376)
the user-space and kernel-space CPU utilization (which is now in milliseconds) to arrive at the total CPU utilization.

##### Comparison between metrics in `top` output and in `/proc/$PID/stat` file

The `%CPU` reported for a process in `top` or `htop` output is in the range `[0, n*100]`, where `n` is the number of cores
available on the machine. For example, if a process runs two threads on a two-core machine, with each thread utilizing
about 60% of each core, `top` or `htop` will report `%CPU` as `120.0` (or close to it).

Applying the calculations from the previous section to corresponding values in the process's `/proc/{pid}/stat` file,
the results match up with what `top` or `htop` report.

##### Comparison between metrics in `/proc/$PID/stat` file and in Agent + Beats `/stats` API output

Using the following script for a host running Agent and one child Beat (excluding any monitoring Beats), we can see that
the metrics in the `/proc/$PID/stat` file match up with those in the Agent + Beats `/stats` API output.

```shell
#!/bin/bash

BEAT_CPU_MS_TOTAL=$(sudo curl -s -X GET --unix-socket '/opt/Elastic/Agent/data/tmp/PGwsYWcynGUYZEjD872Gs-npqbv-30jS.sock' 'http:/f/stats' | jq '.beat.cpu.total.value')
AGENT_CPU_MS_TOTAL=$(sudo curl -s http://localhost:6791/stats  | jq '.beat.cpu.total.value')

echo "Stats from API outputs: $(($BEAT_CPU_MS_TOTAL + $AGENT_CPU_MS_TOTAL))";

AGENT_PID=403165

AGENT_USER_TICKS=$(cat /proc/$AGENT_PID/stat | cut -d' ' -f14)
AGENT_SYSTEM_TICKS=$(cat /proc/$AGENT_PID/stat | cut -d' ' -f15)
AGENT_TOTAL_TICKS=$(($AGENT_USER_TICKS + $AGENT_SYSTEM_TICKS))
AGENT_TOTAL_MS=$(($AGENT_TOTAL_TICKS * 1000 / 100))

#echo "Agent total ticks: $AGENT_TOTAL_TICKS"
#echo "Agent total ms: $AGENT_TOTAL_MS"

BEAT_PID=431834

BEAT_USER_TICKS=$(cat /proc/$BEAT_PID/stat | cut -d' ' -f14)
BEAT_SYSTEM_TICKS=$(cat /proc/$BEAT_PID/stat | cut -d' ' -f15)
BEAT_TOTAL_TICKS=$(($BEAT_USER_TICKS + $BEAT_SYSTEM_TICKS))
BEAT_TOTAL_MS=$(($BEAT_TOTAL_TICKS * 1000 / 100))

#echo "Beat total ticks: $BEAT_TOTAL_TICKS"
#echo "Beat total ms: $BEAT_TOTAL_MS"

echo "Stats from /proc/PID/stats files: $(($AGENT_TOTAL_MS + $BEAT_TOTAL_MS))"
```

##### Comparison between metrics in Agent + Beats `/stats` API output and in Elasticsearch `metrics-elastic_agent*` indices

This comparison is relatively easy to make.

First, we call the `/stats` APIs on the machine where Agent and its Beats are running. For example, with an Agent running
one Beat (excluding monitoring Beats):

```shell
$ sudo curl -s http://localhost:6791/stats  | jq '.beat.cpu.total.value'
34810
$ sudo curl -s -X GET --unix-socket '/opt/Elastic/Agent/data/tmp/PGwsYWcynGUYZEjD872Gs-npqbv-30jS.sock' 'http:/f/stats' | jq '.beat.cpu.total.value'
795000
```

Then we call the Elasticsearch `_search` API on `metrics-elastic_agent*` indices, keeping the query filters the same as
the query being done by Fleet UI, but only considering the latest documents for each `elastic_agent.process`, since the
CPU utilization metrics are counter metrics.

```
curl -s -u $ES_USER:$ES_PASS -H 'Content-Type: application/json' 'https://test-cpu.es.us-central1.gcp.cloud.es.io:9243/metrics-elastic_agent*/_search' -d '{
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ],
  "collapse": {
    "field": "elastic_agent.process"
  },
  "_source": [
    "@timestamp",
    "system.process.cpu.total.value"
  ],
  "query": {
    "bool": {
      "must": [
        {
          "terms": {
            "_tier": [
              "data_hot"
            ]
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "now-5m"
            }
          }
        },
        {
          "terms": {
            "elastic_agent.id": [
              "62efabf2-21ec-4764-b5b5-32f7c6ce509b"
            ]
          }
        },
        {
          "bool": {
            "filter": [
              {
                "bool": {
                  "should": [
                    {
                      "term": {
                        "data_stream.dataset": "elastic_agent.elastic_agent"
                      }
                    }
                  ]
                }
              }
            ]
          }
        }
      ]
    }
  }
}' | jq -r '.hits.hits[]._source | [ ."@timestamp", .system.process.cpu.total.value ] | @tsv'
```
```
2024-01-05T23:21:59.164Z	794990
2024-01-05T23:21:59.164Z	34810
```

We can see that the metrics in the Agent + Beats `/stats` API outputs match up with those in the Elasticsearch
`metrics-elastic_agent*` indices.

## Unanswered Questions

1. Why do we divide by 10000 (`params._interval`) in the ES query?
2. Why do we use a `10s` interval for the derivative aggregation in the ES query? Is this related to the division above?
