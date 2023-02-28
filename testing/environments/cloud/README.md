# Cloud-first testing

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