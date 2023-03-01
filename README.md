# Elastic Agent

## Developer docs

The source files for the general Elastic Agent documentation are currently stored
in the [observability-docs](https://github.com/elastic/observability-docs) repo. The following docs are only focused on getting developers started building code for Elastic Agent.

### Changelog

The changelog for the Elastic Agent is generated and maintained using the [elastic-agent-changelog-tool](https://github.com/elastic/elastic-agent-changelog-tool). Read the [installation](https://github.com/elastic/elastic-agent-changelog-tool/blob/8.7/docs/install.md)
and [usage](https://github.com/elastic/elastic-agent-changelog-tool/blob/8.7/docs/usage.md#im-a-developer) instructions to get started.

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

## Testing

Prerequisites:
- installed [mage](https://github.com/magefile/mage)
- [Docker](https://docs.docker.com/get-docker/)
- [X-pack](https://github.com/elastic/beats/tree/8.7/x-pack) to pre-exist in the parent folder of the local Git repository checkout
- [elastic-agent-changelog-tool](https://github.com/elastic/elastic-agent-changelog-tool) to add changelog fragments for changelog generation

If you are on a Mac with M1 chip, don't forget to export some docker variable to be able to build for AMD
```
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0
export DOCKER_DEFAULT_PLATFORM=linux/amd64
```

If you are on a Mac with M1 chip, don't forget to export some docker variable to be able to build for AMD
```
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0
export DOCKER_DEFAULT_PLATFORM=linux/amd64
```

If you are on a Mac with M1 chip, don't forget to export some docker variable to be able to build for AMD
```
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0
export DOCKER_DEFAULT_PLATFORM=linux/amd64
```

If you are on a Mac with M1 chip, don't forget to export some docker variable to be able to build for AMD
```
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0
export DOCKER_DEFAULT_PLATFORM=linux/amd64
```

In Linux operating systems that you can not run docker as a root user you need to follow [linux-postinstall steps](https://docs.docker.com/engine/install/linux-postinstall/)

### Testing docker container

Running Elastic Agent in a docker container is a common use case. To build the Elastic Agent and create a docker image run the following command:

```
DEV=true SNAPSHOT=true PLATFORMS=linux/amd64 PACKAGES=docker mage package
```

If you are in the 7.13 branch, this will create the `docker.elastic.co/beats/elastic-agent:7.13.0-SNAPSHOT` image in your local environment. Now you can use this to for example test this container with the stack in elastic-package:

```
elastic-package stack up --version=7.13.0-SNAPSHOT -v
```

Please note that the docker container is built in both standard and 'complete' variants.
The 'complete' variant contains extra files, like the chromium browser, that are too large
for the standard variant.

### Testing Elastic Agent on Kubernetes

#### Prerequisites
- create kubernetes cluster using kind, check [here](https://github.com/elastic/beats/blob/8.7/metricbeat/module/kubernetes/_meta/test/docs/README.md) for details
- deploy kube-state-metrics, check [here](https://github.com/elastic/beats/blob/8.7/metricbeat/module/kubernetes/_meta/test/docs/README.md) for details
- deploy required infrastructure:
    - for elastic agent in standalone mode: EK stack or use [elastic cloud](https://cloud.elastic.co), check [here](https://github.com/elastic/beats/blob/8.7/metricbeat/module/kubernetes/_meta/test/docs/README.md) for details
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
