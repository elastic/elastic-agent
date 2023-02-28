package e2e

import (
	"flag"
	"testing"

	tools "github.com/elastic/elastic-agent/e2e/tools"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var clusterConfigPath string
var clusterConfig ClusterConfig

func init() {
	flag.StringVar(&clusterConfigPath, "config", "./cluster-digest.yml", "Path to cluster config")
}

func TestElasticAgentUpgrade(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Basic Suite")
}

var _ = BeforeSuite(func() {
	By("validating flags and config")
	Expect(clusterConfigPath).NotTo(BeZero(), "Please make sure --config is set correctly.")

	c, err := ReadConfig(clusterConfigPath)
	Expect(err).NotTo(HaveOccurred())
	clusterConfig = c
})

var _ = Describe("Smoketests", func() {
	Describe("Test config", func() {
		It("has correct cluster data", func() {
			Expect(clusterConfig.ESConfig.Host).To(ContainSubstring("elastic-cloud.com:443"))
		})
		Describe("Elastic Agent Install", func() {
			BeforeEach(func() {
				By("Downloading elastic agent")
				Expect(tools.DownloadElasticAgent("8.6.1")).To(Succeed())
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

})
