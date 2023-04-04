### E2E tests

#### Dependencies

[oblt-cli](https://studious-disco-k66oojq.pages.github.io)

### Try it locally

0. Setup vault
`oblt-cli` stores cluster secrets in vault. 
Export the environment variable `VAULT_TOKEN` or have the `~/.vault-token` file created.
For further details about how to configure Vault check [the Vault documentation](https://github.com/elastic/infra/tree/master/docs/vault)

1. Install and configure [oblt-cli](https://studious-disco-k66oojq.pages.github.io)

2. Create a cluster for e2e tests:

In the `testing` directory:

```
GITHUB_TOKEN=... SLACK_CHANNEL=... make create-cluster
```

Specify a `GITHUB_TOKEN` with configured SSO and the `SLACK_CHANNEL` - the slack channel identifier to send messages about cluster state. 

It uses [oblt-cli](https://studious-disco-k66oojq.pages.github.io) to spin up an ephemeral cluster with ES, Kibana, APM and fleet.

The cluster specs are located in `test-cluster.yml.tpl`. 

The `create-cluster` target creates 2 files: 
* `cluster-info.json` - Basic cluster information
* `cluster-digest.yml` - a sensitive YAML containing all required endpoints and credentials to be passed to tests in the next step.

3. Run tests:
It's not always easy to run the tests locally because we can already have an elastic-agent installed on our machine. 
Proposal: Let's use devContainers for better experience(for development and troubleshooting).

Install `Remote Development` extension for VSCode. 

In VSCode:
`cmd+shift+p` -> `Dev Containers: Open Folder in Container` -> choose path to the `testing` directory

Open integrated VSCode terminal:

```
cd e2e
AGENT_VERSION=8.6.0 go test -v -timeout 300s -run ^TestElasticAgentUpgrade$ github.com/elastic/elastic-agent/testing/e2e
```

The credentials and endpoints in the `cluster-digest.yml` are used by e2e tests to communicate with created cluster.

Next, the script runs a series of tests, which include:

* Downloading and unpacking the Elastic Agent v8.6.0
* Enrolling the agent
* Upgrading the agent
* Verifying that the agent is healthy
* Un-enrolling/uninstalling the agent

4. `make destroy-cluster`
Destroy the cluster

### Using devContainer
To emulate different unix operating systems and CPU architectures for now we can use devContainers locally. 
But only for development and debugging purposes. In the CI we will use VMs. 

###
Current problems: 
* Downloading and unpacking of elasic-agent is too slow (need help)

### TODO:
 * Use build flags to separate platform dependent utility code  
 * Run on remote vms and windows
 * CI
 * Advanced reporting(aggregate on the host runner) 
 * tracing, telemetry
