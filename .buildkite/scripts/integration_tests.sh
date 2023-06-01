#!/usr/bin/env bash
set -exuo pipefail

export WORKSPACE=`pwd`

if ! command -v gcloud &>/dev/null; then
  echo "Google Cloud SDK is not installed. Installing Google Cloud SDK..."
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list
  curl -S https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
  sudo apt update
  sudo apt-get install google-cloud-sdk -y
  echo "Google Cloud SDK has been installed."
else
  echo "Google Cloud SDK is already installed."
fi

vault kv get -format=json -field=data kv/ci-shared/observability-ingest/cloud/gcp > ./gcp.json
export GOOGLE_APPLICATION_CREDENTIALS=$(realpath ./gcp.json)
export TEST_INTEG_AUTH_GCP_SERVICE_TOKEN_FILE=$(realpath ./gcp.json)  
gcloud auth activate-service-account --key-file $GOOGLE_APPLICATION_CREDENTIALS 2> /dev/null

if ! command -v go &>/dev/null; then
  echo "Go is not installed. Installing Go..."    
  curl -O https://dl.google.com/go/go1.19.9.linux-amd64.tar.gz
  sudo tar -xvf go1.19.9.linux-amd64.tar.gz -C /usr/local
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc  
  source ~/.bashrc
  mkdir $HOME/go
  mkdir $HOME/go/bin
  export PATH=$PATH:/usr/local/go/bin
  echo "Go has been installed."
else
  echo "Go is already installed."
fi

if ! command -v mage &>/dev/null; then
  echo "mage is not installed. Installing mage..."
  git clone https://github.com/magefile/mage $HOME/magesrc
  cd $HOME/magesrc
  go run bootstrap.go
  cd $WORKSPACE  
  export PATH=$PATH:$HOME/go/bin
  echo "mage has been installed."
else
  echo "mage is already installed."
fi

#ESS
vault kv get -field apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod > ./apiKey
export TEST_INTEG_AUTH_ESS_APIKEY_FILE=$(realpath ./apiKey)

# Run integration tests
mage integration:auth
mage integration:test
