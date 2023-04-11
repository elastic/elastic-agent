import os
from ogc import init, fs

os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", "my-google-service-creds.json")
os.environ.setdefault("GOOGLE_APPLICATION_SERVICE_ACCOUNT", "my-google@**.iam.gserviceaccount.com")
os.environ.setdefault("GOOGLE_PROJECT", "my-project")
os.environ.setdefault("GOOGLE_DATACENTER", "us-central1-a")

deployment = init(
    layout_model=dict(
        instance_size="e2-standard-4",
        name="agent-int-ubuntu",
        provider="google",
        remote_path="/home/ubuntu/agent",
        runs_on="ubuntu-2004-lts",
        scale=1,
        scripts="fixtures/ex_deploy_ubuntu",
        username="ubuntu",
        ssh_private_key=fs.expand_path("~/.ssh/id_rsa"),
        ssh_public_key=fs.expand_path("~/.ssh/id_rsa"),
        ports=["22:22"],
        tags=[],
        labels=dict(
            division="engineering", org="platform", team="ingest", project="agent"
        ),
    ),
)
