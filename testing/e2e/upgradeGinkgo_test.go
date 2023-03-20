package e2e_ginkgo

import (
	"time"

	tools "github.com/elastic/elastic-agent/testing/e2e/tools"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
)

var _ = Describe("Smoketests", func() {

	Describe("Elastic Agent Install and Upgrade", Ordered, func() {
		var enrollmentToken tools.EnrollmentAPIKey

		// Setup: executed once before all specs within this Describe block
		BeforeAll(func() {
			By("Downloading elastic agent")
			Expect(tools.DownloadElasticAgent(agentVersion)).To(Succeed())
		})

		// Spec: The test case
		It("fleet managed: is online after upgrade", func() {
			By("Create policy")
			policy, err := client.CreatePolicy()
			Expect(err).NotTo(HaveOccurred())

			By("Create enrollment token")
			enrollmentToken, err = client.CreateEnrollmentAPIKey(policy)
			Expect(err).NotTo(HaveOccurred())

			By("Installing & enrolling EA")
			// gexec.Start() returns a session object that can be used to interact with the process
			session, err := tools.EnrollElasticAgent(clusterConfig.FleetConfig.Url, enrollmentToken.APIKey, agentVersion)
			Expect(err).NotTo(HaveOccurred())
			Eventually(session, 2*time.Minute).Should(gexec.Exit(0))

			By("Wait for agent to be healthy(online)")
			Eventually(client.GetAgentStatus).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(BeEquivalentTo("online"))

			By("Upgrade elastic agent")
			Expect(client.UpgradeAgent("8.6.1")).To(Succeed())

			By("Wait for agent to be healthy(online)")
			Eventually(client.GetAgentStatus).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(BeEquivalentTo("online"))
			Expect(client.GetAgentVersion()).To(Equal("8.6.1"))
		})

		// Tear down: executed after search spec
		AfterEach(func() {
			By("Un-enroll agent")
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
