package e2e_ginkgo

import (
	"flag"
	"os"
	"testing"

	tools "github.com/elastic/elastic-agent/testing/e2e/tools"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var clusterConfigPath string
var clusterConfig tools.ClusterConfig
var client *tools.Client
var agentVersion = os.Getenv("AGENT_VERSION")

func init() {
	flag.StringVar(&clusterConfigPath, "config", "./cluster-digest.yml", "Path to cluster config")
}

func TestElasticAgentUpgrade(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Basic Suite")
}

var _ = BeforeSuite(func() {
	By("validating flags and config")
	Expect(clusterConfigPath).NotTo(BeZero(), "Make sure --config is set correctly.")
	var err error
	clusterConfig, err = tools.ReadConfig(clusterConfigPath)
	Expect(err).NotTo(HaveOccurred())
	client, err = tools.NewClient(&clusterConfig)
	Expect(err).NotTo(HaveOccurred())
})
