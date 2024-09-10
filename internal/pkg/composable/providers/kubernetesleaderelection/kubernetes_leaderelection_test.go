// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetesleaderelection

import (
	"context"
	"testing"
	"time"

	autodiscoverK8s "github.com/elastic/elastic-agent-autodiscover/kubernetes"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/elastic/elastic-agent-libs/logp"

	ctesting "github.com/elastic/elastic-agent/internal/pkg/composable/testing"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

const namespace = "default"
const leaseName = "agent-lease-test"

// createLease creates a new lease resource
func createLease() *v1.Lease {
	lease := &v1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      leaseName,
			Namespace: namespace,
		},
	}
	return lease
}

// applyLease applies the lease
func applyLease(client kubernetes.Interface, lease *v1.Lease, firstTime bool) error {
	var err error
	if firstTime {
		_, err = client.CoordinationV1().Leases(namespace).Create(context.Background(), lease, metav1.CreateOptions{})
		return err
	}
	_, err = client.CoordinationV1().Leases(namespace).Update(context.Background(), lease, metav1.UpdateOptions{})
	return err
}

// getLeaseHolder returns the holder identity of the lease
func getLeaseHolder(client kubernetes.Interface) (string, error) {
	lease, err := client.CoordinationV1().Leases(namespace).Get(context.Background(), leaseName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	holder := lease.Spec.HolderIdentity
	if holder == nil {
		return "", err
	}
	return *holder, nil
}

// TestNewLeaderElectionManager will test the leader elector.
// We will try to check if an instance can acquire the lease more than one time. This way, we will know that
// the leader elector starts running again after it has stopped - which happens once a leader loses the lease.
// To make sure that happens we will do the following:
// 1. We will create the lease to be used by the leader elector.
// 2. We will create two context providers - in the default context, this would mean two nodes, each one with an agent running.
// We will wait for one of the agents, agent1, to acquire the lease, before starting the other.
// 3. We force the lease to be acquired by the other agent, agent2.
// 4. We will force the lease to be acquired by the agent1 again. To avoid the agent2 reacquiring it multiple times,
// we will stop this provider and make sure the agent1 can reacquire it.
func TestNewLeaderElectionManager(t *testing.T) {
	client := k8sfake.NewSimpleClientset()

	lease := createLease()
	// create the lease that leader election will be using
	err := applyLease(client, lease, true)
	require.NoError(t, err)

	// Create the provider
	logger := logp.NewLogger("test_leaderelection")

	leaseDuration := 3
	leaseRenewDeadline := 2
	leaseRetryPeriod := 1

	c := map[string]interface{}{
		"leader_lease":         leaseName,
		"leader_leaseduration": leaseDuration,
		"leader_renewdeadline": leaseRenewDeadline,
		"leader_retryperiod":   leaseRetryPeriod,
	}
	cfg, err := config.NewConfigFrom(c)
	require.NoError(t, err)

	getK8sClientFunc = func(kubeconfig string, opt autodiscoverK8s.KubeClientOptions) (kubernetes.Interface, error) {
		return client, nil
	}
	require.NoError(t, err)

	podNames := [2]string{"agent1", "agent2"}
	cancelFuncs := [2]context.CancelFunc{}

	done := make(chan int, 1)

	// Create two leader election providers representing two agents running
	for i := 0; i < 2; i++ {
		p, err := ContextProviderBuilder(logger, cfg, true)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancelFuncs[i] = cancel
		defer cancel()

		comm := ctesting.NewContextComm(ctx)

		t.Setenv("POD_NAME", podNames[i])
		go func() {
			_ = p.Run(ctx, comm)
		}()

		if i == 1 {
			break
		}

		// We need to wait for the first agent to acquire the lease, so we can POD_NAME environment variable again
		go func() {
			expectedLeader := leaderElectorPrefix + podNames[i]
			for {
				holder, err := getLeaseHolder(client)
				require.NoError(t, err)

				if holder == expectedLeader {
					done <- 1
					break
				}
			}
		}()

		select {
		case <-done:
		case <-time.After(time.Duration(leaseDuration+leaseRetryPeriod) * 30 * time.Second):
			require.FailNow(t, "Timeout"+
				" while waiting for the first pod to acquire the lease. This should not happen. Consider increasing "+
				"the timeout.")
		}
	}

	go func() {
		// At this point the current holder is agent1. Let's change it to agent2.
		for {
			// Force the lease to be applied again, so a new leader is elected.
			intermediateHolder := "does-not-matter"
			lease.Spec.HolderIdentity = &intermediateHolder
			err = applyLease(client, lease, false)
			require.NoError(t, err)

			var currentHolder string
			for {
				currentHolder, err = getLeaseHolder(client)
				require.NoError(t, err)

				// In this case, we already have an agent as holder
				if currentHolder == leaderElectorPrefix+podNames[0] || currentHolder == leaderElectorPrefix+podNames[1] {
					break
				}
			}

			if currentHolder == leaderElectorPrefix+podNames[1] {
				done <- 1
				break
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Duration(leaseDuration+leaseRetryPeriod) * 30 * time.Second):
		require.FailNow(t, "Timeout "+
			" while waiting for agent2 to acquire the lease. This should not happen. Consider increasing "+
			"the timeout.")
	}

	// Now that the holder is agent2, let's wait for agent1 to be reelected.
	// To avoid having to wait very long, the context of agent2 will be canceled so the leader elector will not be
	// running anymore. This way there is only one instance fighting to acquire the lease.
	cancelFuncs[1]()
	go func() {
		for {
			// Force the lease to be applied again, so a new leader is elected.
			intermediateHolder := "does-not-matter"
			lease.Spec.HolderIdentity = &intermediateHolder
			err = applyLease(client, lease, false)
			require.NoError(t, err)

			var currentHolder string
			for {
				currentHolder, err = getLeaseHolder(client)
				require.NoError(t, err)

				// In this case, we already have an agent as holder
				if currentHolder == leaderElectorPrefix+podNames[0] || currentHolder == leaderElectorPrefix+podNames[1] {
					break
				}
			}

			if currentHolder == leaderElectorPrefix+podNames[0] {
				done <- 1
				break
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Duration(leaseDuration+leaseRetryPeriod) * 30 * time.Second):
		require.FailNow(t, "Timeout"+
			" while waiting for agent1 to reacquire the lease. This should not happen. Consider increasing "+
			"the timeout.")
	}

	cancelFuncs[0]()
}
