## Autodiscover provider in Elastic Agent

  

https://www.elastic.co/guide/en/fleet/current/kubernetes-provider.html

  

Kubernetes provider can be configured both in **standalone** and **fleet managed** elastic agent.

a. In  **standalone** elastic agent, user needs to edit the [elastic-agent-standalone-kubernetes.yaml](https://github.com/elastic/elastic-agent/blob/f994f5bfdf68db27902a4175c3b655b4d611cf7c/deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml#L28)
b. In **fleet managed** elastic agent, kubernetes provider is enabled by default with default values. User needs to follow the steps described in the [documentation](https://www.elastic.co/guide/en/fleet/current/advanced-kubernetes-managed-by-fleet.html) to configure it.

Condition based autodiscover is supported both in **fleet managed** elastic agent and in **standalone** elastic agent(see [doc](https://www.elastic.co/guide/en/fleet/current/conditions-based-autodiscover.html)).

Hints based autodiscover is only supported in **standalone** elastic agent(see [doc](https://www.elastic.co/guide/en/fleet/current/hints-annotations-autodiscovery.html)).

  

### Conditions based autodiscover

  

Example:

As an example we will use the redis module.

To automatically identify a Redis Pod and monitor it with the Redis integration, add the following input configuration inside the [Elastic Agent Standalone manifest](https://github.com/elastic/elastic-agent/blob/main/deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml):

```
# Add extra input blocks here, based on conditions
# so as to automatically identify targeted Pods and start monitoring them
# using a predefined integration. For instance:
- name: redis
  type: redis/metrics
  use_output: default
  meta:
    package:
      name: redis
      version: 0.3.6
  data_stream:
    namespace: default
  streams:
    - data_stream:
        dataset: redis.info
        type: metrics
      metricsets:
        - info
      hosts:
        - '${kubernetes.pod.ip}:6379'
      idle_timeout: 20s
      maxconn: 10
      network: tcp
      period: 10s
      condition: ${kubernetes.pod.labels.app} == 'redis'
```

  

What makes this input block dynamic are the variables under hosts block and the condition.

`${kubernetes.pod.ip}` and `${kubernetes.pod.labels.app} == 'redis'`

  

#### High level description

The Kubernetes provider watches for Kubernetes resources and generates mappings from them (similar to events in beats provider). The mappings include those variables([list of variables](https://www.elastic.co/guide/en/fleet/current/kubernetes-provider.html#_provider_for_pod_resources)) for each k8s resource with unique value for each one of them.

Agent composable controller which controls all the providers receives these mappings and tries to match them with the input blogs of the configurations.

This means that for every mapping that the condition matches (`kubernetes.pod.labels.app == redis`), a new input will be created in which the condition will be removed(not needed anymore) and the `kubernetes.pod.ip` variable will be substituted from the value in the same mapping.

The updated complete inputs block will be then forwarded to agent to spawn/update metricbeat and filebeat instances.


### Hints based autodiscover

Standalone elastic agent supports autodiscover based on hints collected from the [Kubernetes Provider](https://www.elastic.co/guide/en/fleet/current/kubernetes-provider.html). The hints mechanism looks for hints in kubernetes pod annotations that have the prefix `co.elastic.hints`. As soon as the Pod is ready, elastic agent checks it for hints and launches the proper configuration for the container. Hints tell elastic agent how to monitor the container by using the proper integration.
The full list of supported hints can be found [here](https://www.elastic.co/guide/en/fleet/current/hints-annotations-autodiscovery.html#_required_hints).

Example:

As an example we will use again redis module.
Add the following annotations to a redis pod. Elastic agent will then initiate a new input with redis module to properly monitor the redis pod.
```
apiVersion: v1 
kind: Pod
metadata:
  name: redis 
  annotations:
    co.elastic.hints/package: redis
    co.elastic.hints/data_streams: info
    co.elastic.hints/info.period: 5m
```

In order to enable hints based autodiscover, user needs to uncomment the following lines in the [Elastic Agent Standalone manifest](https://github.com/elastic/elastic-agent/blob/main/deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml)
1. Add the [init container]((https://github.com/elastic/elastic-agent/blob/c01636e7383a9b2af9a588e0fcf1a4cae7d0d65c/deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml#L697-L709)) that downloads the templates of various packages.
2. Add the [volumeMount](https://github.com/elastic/elastic-agent/blob/c01636e7383a9b2af9a588e0fcf1a4cae7d0d65c/deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml#L783-L785) and [volume](https://github.com/elastic/elastic-agent/blob/c01636e7383a9b2af9a588e0fcf1a4cae7d0d65c/deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml#L824-L826).

The init container will start before the elastic agent pod and will donwload all the templates of packages [supported](https://github.com/elastic/elastic-agent/tree/main/deploy/kubernetes/elastic-agent-standalone/templates.d). 
Elastic agent will then collect from the pods running(through the watchers mechanism) all the hints annotations and will try to match them with the correct package.
In the redis example, it will use the [redis template](https://github.com/elastic/elastic-agent/blob/main/deploy/kubernetes/elastic-agent-standalone/templates.d/redis.yml) and substitute the template variables with the values specified in the annotations. Default values will be used for variables not provided.
A new input will be then created for redis and redis-specific data will start being collected.