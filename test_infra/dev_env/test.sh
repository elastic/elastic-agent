#sudo su buildkite-agent
cd ~
git clone https://github.com/elastic/elastic-agent.git
cd elastic-agent
git checkout ci_install_tools


test_infra/dev_env/install_asdf.sh
source ~/.bashrc
test_infra/dev_env/init_asdf.sh


#mise
curl https://mise.run | sh
export PATH="$HOME/.local/bin:$PATH"
mise install
eval "$(mise activate bash --shims)"