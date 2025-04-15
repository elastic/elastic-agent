#sudo su buildkite-agent
cd ~
git clone https://github.com/elastic/elastic-agent.git
cd elastic-agent
git checkout ci_install_tools
source test_infra/dev_env/install_asdf.sh
