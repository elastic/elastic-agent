package elastic_agent_e2e

import (
	"flag"
	"fmt"
	"testing"

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
	if err != nil {
		panic(err)
	}
	fmt.Printf("clusterConfig: %+v", clusterConfig)
})

var _ = Describe("Smoketests", func() {
	Describe("Test config", func() {
		It("has correct cluster data", func() {
			fmt.Println("clusterConfig.ESConfig.Host: ", clusterConfig.ESConfig)
			Expect(clusterConfig.ESConfig.User).To(ContainSubstring("elastic-cloud.com:443"))
		})
	})

	Describe("Elastic Agent", func() {
		It("can connect to ElasticSearch", func() {
			// TODO: implement
		})
	})
})
