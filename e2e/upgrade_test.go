package e2e

import (
	"flag"
	"os"
	"testing"
	"time"

	tools "github.com/elastic/elastic-agent/e2e/tools"
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

	c, err := tools.ReadConfig(clusterConfigPath)
	Expect(err).NotTo(HaveOccurred())
	clusterConfig = c
	c2, err := tools.NewClient(&clusterConfig)
	Expect(err).NotTo(HaveOccurred())
	client = c2
})

var _ = Describe("Smoketests", func() {

	Describe("Elastic Agent Install", Ordered, func() {
		var enrollmentToken tools.EnrollmentAPIKey
		BeforeAll(func() {
			By("Downloading elastic agent")
			Expect(tools.DownloadElasticAgent(agentVersion)).To(Succeed())
			Expect(tools.UnpackTar(agentVersion)).To(Succeed())
		})

		BeforeEach(func() {
			By("Create policy")
			policy, err := client.CreatePolicy()
			Expect(err).NotTo(HaveOccurred())

			By("Create enrollment token")
			enrollmentToken, err = client.CreateEnrollmentAPIKey(policy)
			Expect(err).NotTo(HaveOccurred())
		})

		It("is online when enrolled", func() {
			By("Installing & enrolling EA")
			session, err := tools.EnrollElasticAgent(clusterConfig.FleetConfig.Url, enrollmentToken.APIKey)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session, 2*time.Minute).Should(gexec.Exit(0))

			By("Wait for agent to be healthy(online)")
			Eventually(client.GetAgentStatus).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(BeEquivalentTo("online"))
		})

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
