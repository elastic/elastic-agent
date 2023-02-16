package elastic_agent_e2e

import (
	"flag"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var clusterConfigPath string
var clusterConfig ClusterConfig

func init() {
	flag.StringVar(&clusterConfigPath, "config", "", "Path to cluster config")
}

func TestObltCliTest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Basic Suite")
}

var _ = BeforeSuite(func() {
	By("validating flags and config")
	Expect(clusterConfigPath).NotTo(BeZero(), "Please make sure --config is set correctly.")

	clusterConfig, err := ReadConfig(clusterConfigPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("clusterConfig: %+v", clusterConfig)
})

var _ = Describe("Congiguration Smoke ", func() {
	Describe("ES config", func() {
		It("has correct host", func() {
			Expect(clusterConfig.ESConfig.Host).To(ContainSubstring("elastic-cloud.com:443"))
		})

		It("has correct username", func() {
			Expect(clusterConfig.ESConfig.User).NotTo(BeEmpty())
		})
	})

	Describe("Kibana Config", func() {
		It("has correct host", func() {
			Expect(clusterConfig.ESConfig.Host).To(ContainSubstring("elastic-cloud.com:443"))
		})

		It("has correct username", func() {
			Expect(clusterConfig.ESConfig.User).NotTo(BeEmpty())
		})
	})
})
