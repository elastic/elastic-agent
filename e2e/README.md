### E2E tests

#### Dependencies

[oblt-cli](https://studious-disco-k66oojq.pages.github.io)
[ginkgo](https://onsi.github.io/ginkgo/#getting-started)

#### Try its
* install oblt-cli 
* `make -C test create-cluster` (~6-8 minutes)
* `make -C test run-tests`
* `make -C test destroy-cluster`

How it Works
The process begins by spinning up the stack using oblt-cli, as outlined in the Makefile under the "create-cluster" command.

`oblt-cli` uses `test-cluster.yml.tpl` as cluster definition to create the cluster.
`oblt-cli` outputs the `cluster-digest.yml` file with all required endpoints and credentials, for example: 

```
---
elasticsearch:
  ELASTICSEARCH_HOST: https://the_host:443  
  ELASTICSEARCH_PASSWORD: ...
  ELASTICSEARCH_USERNAME: ...
kibana:
  ...
apm:
  ...
fleet:
  ...
users:
  - admin
  - apm_server_user
  - beats_user
```

Next, the script runs a series of tests, which include:

* Downloading and unpacking the Elastic Agent v8.6.0
* Enrolling the agent
* Upgrading the agent
* Verifying that the agent is healthy
* Unenrolling/uninstalling the agent

Test framework reads the `cluster-digest.yml` and created the `clusterConfig` variable.

Once the tests are complete, the cluster is destroyed using the "destroy-cluster" command in the Makefile.

#### For a smoother debugging experience, we recommend using devContainer.

### TODO:
 * Version picker 
 * Cross platform elastic agent directory naming
 * Run remote vms and windows
 * CI
 * Fancy reporting(aggregate on the host runner) 



