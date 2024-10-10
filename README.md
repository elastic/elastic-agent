# Elastic Agent

[![Build status](https://badge.buildkite.com/1d35bb40427cc6833979645b61ea214fc4b686a2ffe3a68bdf.svg)](https://buildkite.com/elastic/elastic-agent)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=elastic_elastic-agent&metric=coverage)](https://sonarcloud.io/summary/new_code?id=elastic_elastic-agent)

## Architecture and Internals

- [Agent architecture](docs/architecture.md)
- [Component spec files](docs/component-specs.md)
- [Policy configuration](docs/agent-policy.md)

## Official Documentation

See https://www.elastic.co/guide/en/fleet/current/index.html.

The source files for the offical Elastic Agent documentation are currently stored
in the [ingest-docs](https://github.com/elastic/ingest-docs/tree/main/docs/en/ingest-management) repository.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Developing

The following are exclusively focused on getting developers started building code for Elastic Agent.

### Development Installations

> :warning: Development installations are not officially supported and are intended for Elastic Agent developers.

If you are an Elastic employee, you already have an Information Security managed Elastic Agent installed on your machine for endpoint protection.
This prevents you from installing the Elastic Agent a second time for development without using a VM or Docker container. To eliminate this point
of friction, Elastic Agent has a development mode that permits installing the Elastic Agent on your machine a second time:

```sh
# All other arguments to the install command are still supported when --develop is specified.
sudo ./elastic-agent install --develop
# The run command also supports the --develop option to allow running without installing when there is another agent on the machine.
./elastic-agent run -e --develop
```

Using the `--develop` option will install the agent in an isolated `Agent-Development` agent directory in the chosen base path.
Development agents enrolled in Fleet will have the `Development` tag added automatically. Using the default base path on MacOS you will see:

```sh
sudo ls /Library/Elastic/
Agent
Agent-Development
```

The `elastic-agent` command in the shell is replaced with `elastic-development-agent` to interact with the development agent:

```sh
# For a privileged agent
sudo elastic-development-agent status
# For an unprivileged agent
sudo -u elastic-agent-user elastic-development-agent status
```

The primary restriction of `--develop` installations is that they cannot run Elastic Defend. Defend requires the agent to be
in the default path, the same restrictions applies for the `--base-path` option. All other integrations should be usable provided
conflicting configurations are changed ahead of time. For example two agents cannot bind to the same `agent.monitoring.http.port`
to expose their monitoring servers.

### Test Framework

In addition to standard Go tests, changes to the Elastic Agent are always installed and tested on cross-platform virtual machines.
For details on writing and running tests see the [Test Framework Developer Guide](docs/test-framework-dev-guide.md).

### Changelog

The changelog for the Elastic Agent is generated and maintained using the [elastic-agent-changelog-tool](https://github.com/elastic/elastic-agent-changelog-tool). Read the [installation](https://github.com/elastic/elastic-agent-changelog-tool/blob/main/docs/install.md)
and [usage](https://github.com/elastic/elastic-agent-changelog-tool/blob/main/docs/usage.md#im-a-developer) instructions to get started.

The changelog tool produces fragement files that are consolidated to generate a changelog for each release. Each PR containing a change with user
impact (new feature, bug fix, etc.) must contain a changelog fragement describing the change. There is a GitHub action in CI that will fail
if a PR does not contain a changelog fragment. For PRs that should not have a changelog entry, use the "skip-changelog" label to bypass
this check.

A simple example of a changelog fragment is below for reference:

```yml
kind: bug-fix
summary: Fix a panic caused by a race condition when installing the Elastic Agent.
pr: https://github.com/elastic/elastic-agent/pull/823
```

### Packaging

Prerequisites:
- installed [mage](https://github.com/magefile/mage)
- [Docker](https://docs.docker.com/get-docker/)
- [beats](https://github.com/elastic/beats) to pre-exist in the parent folder of the local Git repository checkout if, and only if, packaging with `EXTERNAL=false` to package the beats as well
- [elastic-agent-changelog-tool](https://github.com/elastic/elastic-agent-changelog-tool) to add changelog fragments for changelog generation

To build a local version of the agent for development, run the command below. The following platforms are supported:
* darwin/amd64
* darwin/arm64
* linux/amd64
* linux/arm64
* windows/amd64

```sh
# DEV=true disable signature verification to allow replacing binaries in the components sub-directory of the package.
# EXTERNAL=true downloads the matching version of the binaries that are packaged with agent (Beats for example).
# SNAPSHOT=true indicates that this is a snapshot version and not a release version.
# PLATFORMS=linux/amd64 builds an agent that will run on 64 bit Linux systems.
# PACKAGES=tar.gz produces a tar.gz package
DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64 PACKAGES=tar.gz mage -v package
```

The resulting package will be produced in the build/distributions directory. The version is controlled by the value in [version.go](version/version.go).
To install the agent extract the package and run the install command:

```sh
cd build/distributions
tar xvfz build/distributions/elastic-agent-8.8.0-SNAPSHOT-darwin-aarch64.tar.gz
cd build/distributions/elastic-agent-8.8.0-SNAPSHOT-darwin-aarch64
sudo elastic-agent install
```

For basic use the agent binary can be run directly, with the `sudo elastic-agent run` command.

#### Packaging for other architectures
When packaging for an architecture different than the host machine,
you might face the following error:
```
exec /crossbuild: exec format error
```

If that happens, enable
[`multiarch/qemu-user-static`](https://github.com/multiarch/qemu-user-static)
is to enable an execution of different multi-architecture containers
by QEMU and binfmt_misc:

```
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

### Docker

Running Elastic Agent in a docker container is a common use case. To build the Elastic Agent and create a docker image run the following command:

```
# Use PLATFORMS=linux/arm64 if you are using an ARM based Mac.
DEV=true SNAPSHOT=true PLATFORMS=linux/amd64 PACKAGES=docker mage package
```

If you are in the 7.13 branch, this will create the `docker.elastic.co/beats/elastic-agent:7.13.0-SNAPSHOT` image in your local environment. Now you can use this to for example test this container with the stack in elastic-package:

```
elastic-package stack up --version=7.13.0-SNAPSHOT -v
```

Please note that the docker container is built in standard, 'service', 'cloud' and 'complete' variants. The variants technical specificities can be found [here](https://github.com/elastic/elastic-agent/blob/main/dev-tools/packaging/templates/docker/Dockerfile.elastic-agent.tmpl).
- The 'service' variant contains python libs and connectors that allows it to collect data using [search_connectors](https://www.elastic.co/guide/en/enterprise-search/current/connectors.html).
- The 'cloud' variant is the one used for ESS deployment.
- The 'complete' variant contains extra files, like the chromium browser, that are too large
for the standard variant which allows this docker image to run Synthetics.


### Testing Elastic Agent on Kubernetes

#### Prerequisites
- create kubernetes cluster using kind, check [here](https://github.com/elastic/beats/blob/main/metricbeat/module/kubernetes/_meta/test/docs/README.md) for details
- deploy kube-state-metrics, check [here](https://github.com/elastic/beats/blob/main/metricbeat/module/kubernetes/_meta/test/docs/README.md) for details
- deploy required infrastructure:
    - for elastic agent in standalone mode: EK stack or use [elastic cloud](https://cloud.elastic.co), check [here](https://github.com/elastic/beats/blob/main/metricbeat/module/kubernetes/_meta/test/docs/README.md) for details
    - for managed mode: use [elastic cloud](https://cloud.elastic.co) or bring up the stack on docker and then connect docker network with kubernetes kind nodes:
  ```
  elastic-package stack up -d -v
  docker network connect elastic-package-stack_default <kind_container_id>
  ```

1. Build elastic-agent:
```bash
DEV=true PLATFORMS=linux/amd64 PACKAGES=docker mage package
```

Use environmental variables `GOHOSTOS` and `GOHOSTARCH` to specify PLATFORMS variable accordingly. eg.
```bash
❯ go env GOHOSTOS
darwin
❯ go env GOHOSTARCH
amd64
```

2. Build docker image:
```bash
cd build/package/elastic-agent/elastic-agent-linux-amd64.docker/docker-build
docker build -t custom-agent-image .
```
3. Load this image in your kind cluster:
```
kind load docker-image custom-agent-image:latest
```
4. Deploy agent with that image:
- download all-in-ome manifest for elastic-agent in standalone or managed mode, change version if needed
```
ELASTIC_AGENT_VERSION="8.0"
ELASTIC_AGENT_MODE="standalone"     # ELASTIC_AGENT_MODE="managed"
curl -L -O https://raw.githubusercontent.com/elastic/elastic-agent/${ELASTIC_AGENT_VERSION}/deploy/kubernetes/elastic-agent-${ELASTIC_AGENT_MODE}-kubernetes.yaml
```
- Modify downloaded manifest:
    - change image name to the one, that was created in the previous step and add `imagePullPolicy: Never`:
    ```
    containers:
      - name: elastic-agent
        image: custom-agent-image:latest
        imagePullPolicy: Never
    ```
    - set environment variables accordingly to the used setup.

  Elastic-agent in standalone mode: set `ES_USERNAME`, `ES_PASSWORD`,`ES_HOST`.

  Elastic-agent in managed mode: set `FLEET_URL` and `FLEET_ENROLLMENT_TOKEN`.

- create
```
kubectl apply -f elastic-agent-${ELASTIC_AGENT_MODE}-kubernetes.yaml
```
5. Check status of elastic-agent:
```
kubectl -n kube-system get pods -l app=elastic-agent
```

## Testing on Elastic Cloud

Elastic employees can create an Elastic Cloud deployment with a locally
built Elastic Agent, by pushing images to an internal Docker repository. The images will be
based on the SNAPSHOT images with the version defined in `version/version.go`.

Prerequisite to running following commands is having `terraform` installed and running `terraform init` from within `testing/environments/cloud`.

Running a shorthand `make deploy_local` in `testing/environments/cloud` will build Agent, tag the docker image correctly, push it to the repository and deploy to Elastic Cloud.

For more advanced scenarios:
Running `make build_elastic_agent_docker_image` in `testing/environments/cloud` will build and push the images.
Running `make push_elastic_agent_docker_image` in `testing/environments/cloud` will publish built docker image to CI docker repository.

Once docker images are published you can run `EC_API_KEY=your_api_key make apply` from `testing/environments/cloud` directory to deploy them to Elastic Cloud.
To get `EC_API_KEY` follow [this guide](https://www.elastic.co/guide/en/cloud/current/ec-api-authentication.html)

The custom images are tagged with the current version, commit and timestamp. The
timestamp is included to force a new Docker image to be used, which enables pushing new
binaries without recreating the deployment.

To specify custom images create your `docker_image.auto.tfvars` file similar to `docker_image.auto.tfvars.sample`.

You can also use `mage cloud:image` and `mage cloud:push` respectively from repo root directory.
To deploy your changes use `make apply` (from `testing/environments/cloud`) with `EC_API_KEY` instead of `make deploy_local` described above.

SNAPSHOT images are used by default. To use non-snapshot image specify `SNAPSHOT=false` explicitly.

## Updating dependencies/PRs
Even though we prefer `mage` to our automation, we still have some
rules implemented on our `Makefile` as well as CI will use the
`Makefile`. CI will run `make check-ci`, so make sure to run it
locally before submitting any PRs to have a quicker feedback instead
of waiting for a CI failure.

### Generating the `NOTICE.txt` when updating/adding dependencies
To do so, just run `make notice`, this is also part of the `make
check-ci` and is the same check our CI will do.

At some point we will migrate it to mage (see discussion on
https://github.com/elastic/elastic-agent/pull/1108 and on
https://github.com/elastic/elastic-agent/issues/1107). However until
we have the mage automation sorted out, it has been removed to avoid
confusion.
