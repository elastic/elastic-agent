package e2e_ginkgo

import (
	"flag"
	"os"
	"testing"
	"time"

	tools "github.com/elastic/elastic-agent/testing/e2e/tools"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
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

var _ = Describe("Smoketests", func() {

	Describe("Elastic Agent Install and Upgrade", Ordered, func() {
		var enrollmentToken tools.EnrollmentAPIKey

		// Setup: executed once before all specs withing this Describe block
		BeforeAll(func() {
			By("Downloading elastic agent")
			// Expect(tools.DownloadElasticAgent(agentVersion)).To(Succeed())
		})
		// Setup: executed before each spec withing this Describe block
		// I.e. we Create a new policy and token before each spec
		BeforeEach(func() {
			By("Create policy")
			policy, err := client.CreatePolicy()
			Expect(err).NotTo(HaveOccurred())

			By("Create enrollment token")
			enrollmentToken, err = client.CreateEnrollmentAPIKey(policy)
			Expect(err).NotTo(HaveOccurred())
		})

		// Spec: The test case
		It("is online after upgrade", func() {
			By("Installing & enrolling EA")
			// gexec.Start() returns a session object that can be used to interact with the process
			session, err := tools.EnrollElasticAgent(clusterConfig.FleetConfig.Url, enrollmentToken.APIKey, agentVersion)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session, 2*time.Minute).Should(gexec.Exit(0))

			By("Wait for agent to be healthy(online)")
			Eventually(client.GetAgentStatus).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(BeEquivalentTo("online"))

			By("Upgrade elasic agent")
			Expect(client.UpgradeAgent("8.6.1")).To(Succeed())

			By("Wait for agent to be healthy(online)")
			Eventually(client.GetAgentStatus).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(BeEquivalentTo("online"))
			Expect(client.GetAgentVersion()).To(Equal("8.6.1"))
		})

		// Tear down: executed after seach spec
		AfterEach(func() {
			By("Unenroll agent")
			client.UnEnrollAgent()
			Eventually(client.GetAgentStatus).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(BeEquivalentTo(""))

			By("Uninstall elastic agent")
			session, err := tools.UninstallAgent()
			Expect(err).NotTo(HaveOccurred())
			Eventually(session, 1*time.Minute).Should(gexec.Exit(0))
		})

		AfterAll(func() {
			// TODO delete ea
		})
	})
})
