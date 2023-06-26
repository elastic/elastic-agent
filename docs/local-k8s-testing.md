# Run/Test local build of agent on k8s cluster

## Prerequisites

- Install [skaffold](https://skaffold.dev/docs/install/)
- Install [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
- Install a local k8s distribution and create a cluster:
    - [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
    - [k3d](https://k3d.io/v5.5.1/#installation)
    - [minikube](https://minikube.sigs.k8s.io/docs/start/) (not tested)

## Quickstart (the hard way)

#### Standalone or managed mode
There are 2 distinct profiles available (pretty self-explanatory):
- `elastic-agent-standalone`
- `elastic-agent-managed`

One of those profiles must always be specified in a skaffold command (using the `-p` or `--profile` option), for sake of brevity we are gonna list only examples with standalone profile

### Prepare environment variables
In order to run agent on a local k8s cluster we need to set some environment variables in `deploy/skaffold/.env` (we can use `.env.example`). Those environment variables must point to a running elastic stack installation.

#### Standalone mode
```shell
# standalone elastic agent vars
ES_HOST=https://<elasticsearch host>:443
ES_USERNAME=elastic
ES_PASSWORD=changeme
```

#### Managed mode
```shell
# managed elastic agent vars
FLEET_URL=https://<fleet host>:443
FLEET_ENROLLMENT_TOKEN=<enrollment token>
```

### Run agent 

In order to just deploy agent on your local cluster, open a terminal and then execute


```shell
skaffold run -p elastic-agent-standalone
```
and the output should be something similar to this:
```shell
Generating tags...
 ...
Checking cache...
 - docker.elastic.co/beats/elastic-agent: Found Locally
Starting test...
Starting pre-render hooks...
Completed pre-render hooks
Tags used in deployment:
 ...
Starting deploy...
 ...
 - serviceaccount/elastic-agent-standalone created
 - role.rbac.authorization.k8s.io/elastic-agent-standalone created
 - role.rbac.authorization.k8s.io/elastic-agent-standalone-kubeadm-config created
 - clusterrole.rbac.authorization.k8s.io/elastic-agent-standalone created
 - rolebinding.rbac.authorization.k8s.io/elastic-agent-standalone created
 - rolebinding.rbac.authorization.k8s.io/elastic-agent-standalone-kubeadm-config created
 - clusterrolebinding.rbac.authorization.k8s.io/elastic-agent-standalone created
 - configmap/agent-node-datastreams created
 - configmap/fleet-es-configmap-95bb9gfkkt created
 - daemonset.apps/elastic-agent-standalone created
Waiting for deployments to stabilize...
Deployments stabilized in 14.411071ms
You can also run [skaffold run --tail] to get the logs
```

Once you are done, remove the deployments with:
```shell
skaffold delete  -p elastic-agent-standalone
```


### Debug agent
The elastic agent can be debugged by connecting a debugger client to the debugger port (forwarded automatically on localhost).

If we run the command below (the `--tail=false` is there only to disable the streaming of logs on stdout):
```shell
skaffold debug -p elastic-agent-standalone --tail=false
```
we should have something similar to the output below

```shell
Generating tags...
 ...
Checking cache...
 ...
Starting pre-render hooks...
Completed pre-render hooks
Tags used in deployment:
 ...
Starting deploy...
Loading images into kind cluster nodes...
 ...
Images loaded in 35.802479ms
 ... <a bunch of k8s resources created>
Waiting for deployments to stabilize...
Deployments stabilized in 7.654873ms
Listing files to watch...
 - docker.elastic.co/beats/elastic-agent
Press Ctrl+C to exit
Not watching for changes...
WARN[0003] unable to get owner from reference: {apps/v1 DaemonSet elastic-agent-standalone 0c579ec4-319a-4e85-99ec-c409260cb6ce 0xc000f950a0 0xc000f950a1}  subtask=-1 task=DevLoop
Port forwarding pod/elastic-agent-standalone-lgr9d in namespace kube-system, remote port 56268 -> http://127.0.0.1:56268
```
The last line of the output tells us where to connect our debugger ;)
(it's always 56268 unless that port is busy, in which case skaffold will try to increment it until it finds one that can be bound).
The debug session will continue until we hit `Ctrl+C` to stop the debug and start the cleanup

## Quickstart (the easy way)

Check [Google cloud code extension](https://cloud.google.com/code/docs) to do away with the terminal and to have Run/Debug configuration directly in your IDE (if supported)

