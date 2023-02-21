package elastic_agent_e2e

import (
	"flag"
	"fmt"
	"testing"

	tools "github.com/elastic/elastic-agent/test/tools"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	flag.StringVar(&clusterConfigPath, "config", "", "Path to cluster config")
}

func TestElasticAgent(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Basic Suite")
}

var _ = BeforeSuite(func() {
	By("validating flags and config")
	Expect(clusterConfigPath).NotTo(BeZero(), "Please make sure --config is set correctly.")

	clusterConfig, err := ReadConfig(clusterConfigPath)
	Expect(err).NotTo(HaveOccurred())
	_ = clusterConfig
})

var _ = Describe("Smoketests", func() {
	Describe("Test config", func() {
		It("has correct cluster data", func() {
			fmt.Println("clusterConfig.ESConfig.Host: ", clusterConfig.ESConfig)
			Expect(clusterConfig.ESConfig.Host).To(ContainSubstring("elastic-cloud.com:443"))
		})
	})

	Describe("Elastic Agent Install", func() {
		BeforeAll(func() {
			err := tools.DownloadElasticAgent("8.6.1")
			Expect(err).NotTo(HaveOccurred())
		})
		It("install", func() {
			// TODO validate elastic-agent is installed
		})
		It("enroll", func() {
		})
		It("Upgrade", func() {
			// TODO validate elastic-agent is upgraded
		})

		AfterEach(func() {
			// TODO uninstall elastic-agent
		})

	})
})
