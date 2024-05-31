terraform {
  required_version = ">= 1.0.0"

  required_providers {
    ec = {
      source  = "elastic/ec"
      version = "0.7.0"
    }
  }
}

locals {
  # FIXME there is probably a nicer way to read the .go-version file content
  go_version = trimspace(file("${data.external.golist_dump.result.Root}/.go-version"))
  ssh_user = "buildkite-agent"
  git_repo = "https://github.com/elastic/elastic-agent"
  repo_dir = "/src/elastic-agent"
}

# this is to locate exactly the root of the repo (needed to upload the current repo and to pinpoint files in specific locations within the repo)
data "external" "golist_dump" {
  program = [
    "go", "list", "-json=Root", "github.com/elastic/elastic-agent"
  ]
}


