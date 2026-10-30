// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const (
	browserCASecret   = "browser-ca"
	browserAgentHome  = "/usr/share/elastic-agent"
	browserCAPodLabel = "name=agent-clusterwide-helm-agent"
)

// TestKubernetesAgentBrowserCASecret installs the chart with a CA Secret on the complete
// images, as root and unprivileged, and checks that the agent imports the CAs of the
// Secret into the browser trust store and follows updates of the Secret without a
// restart. That the browser then trusts them is covered by the Heartbeat ESS tests.
func TestKubernetesAgentBrowserCASecret(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  false,
		OS: []define.OS{
			{Type: define.Kubernetes, DockerVariant: "complete"},
			{Type: define.Kubernetes, DockerVariant: "complete-wolfi"},
		},
		Group: define.Kubernetes,
	})

	ctx := context.Background() //nolint:forbidigo // ctx is captured by t.Cleanup in step functions; must outlive the test
	kCtx := k8sGetContext(t, info)
	caPEM := browserCATestCA(t)

	for _, unprivileged := range []bool{false, true} {
		t.Run(fmt.Sprintf("unprivileged=%t", unprivileged), func(t *testing.T) {
			steps := []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepBrowserCACreateSecret(),
				k8sStepHelmDeploy(AgentHelmChartPath, "helm-agent", map[string]any{
					"agent": map[string]any{
						"unprivileged": unprivileged,
						"image": map[string]any{
							"repository": kCtx.agentImageRepo,
							"tag":        kCtx.agentImageTag,
							"pullPolicy": "Never",
						},
						"customCAs": map[string]any{
							"secretName": browserCASecret,
						},
						"presets": map[string]any{
							"clusterWide": map[string]any{
								"extraEnvs": []any{
									map[string]any{"name": "ELASTIC_NETINFO", "value": "false"},
									map[string]any{"name": "ELASTIC_AGENT_BROWSER_CA_RELOAD_INTERVAL", "value": "5s"},
								},
							},
						},
					},
					"kubernetes": map[string]any{
						"enabled": true,
					},
					"outputs": map[string]any{
						"default": map[string]any{
							"type":    "ESPlainAuthAPI",
							"url":     kCtx.esHost,
							"api_key": kCtx.esAPIKey,
						},
					},
				}),
				k8sStepCheckAgentStatus(browserCAPodLabel, 1, "agent", nil),
				k8sStepBrowserCAStoreCount(0, "an empty Secret must not add a CA to the browser trust store"),
				k8sStepBrowserCASetSecret(map[string][]byte{"ca.crt": caPEM}),
				k8sStepBrowserCAStoreCount(1, "a CA added to the Secret must reach the browser trust store without a restart"),
			}
			if !unprivileged {
				steps = append(steps, k8sStepBrowserCAStoreOwner())
			}
			steps = append(steps,
				k8sStepBrowserCASetSecret(map[string][]byte{}),
				k8sStepBrowserCAStoreCount(0, "a CA removed from the Secret must leave the browser trust store without a restart"),
			)

			testNamespace := kCtx.getNamespace(t)
			for _, step := range steps {
				step(t, ctx, kCtx, testNamespace)
			}
		})
	}
}

// browserCATestCA returns a self-signed CA in PEM form.
func browserCATestCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating CA key")
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "elastic-agent browser CA test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err, "creating CA")
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// k8sStepBrowserCACreateSecret creates the CA Secret that the chart mounts, empty.
func k8sStepBrowserCACreateSecret() k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: browserCASecret, Namespace: namespace}}
		require.NoError(t, kCtx.client.Resources(namespace).Create(ctx, secret), "failed to create the CA Secret")
	}
}

// k8sStepBrowserCASetSecret replaces the content of the CA Secret that the chart mounts.
func k8sStepBrowserCASetSecret(data map[string][]byte) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		secret := &corev1.Secret{}
		require.NoError(t, kCtx.client.Resources(namespace).Get(ctx, browserCASecret, namespace, secret), "failed to get the CA Secret")
		secret.Data = data
		require.NoError(t, kCtx.client.Resources(namespace).Update(ctx, secret), "failed to update the CA Secret")
	}
}

// browserCAAgentPod returns the name of the clusterWide agent pod.
func browserCAAgentPod(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) string {
	t.Helper()
	pods := &corev1.PodList{}
	err := kCtx.client.Resources(namespace).List(ctx, pods, func(opt *metav1.ListOptions) {
		opt.LabelSelector = browserCAPodLabel
	})
	require.NoError(t, err, "failed to list the agent pods")
	require.Len(t, pods.Items, 1, "expected one clusterWide agent pod")
	return pods.Items[0].Name
}

// k8sStepBrowserCAStoreCount waits until the browser trust store of the agent pod
// holds want CAs imported by the agent. Updated Secrets reach the pod after the
// kubelet's sync period, hence the long wait.
func k8sStepBrowserCAStoreCount(want int, msg string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		pod := browserCAAgentPod(t, ctx, kCtx, namespace)
		// The agent creates the store only once there is a CA to import.
		cmd := []string{"sh", "-c", fmt.Sprintf(
			"db=%s/.pki/nssdb; [ -f $db/cert9.db ] || exit 0; certutil -L -d sql:$db", browserAgentHome)}
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var stdout, stderr bytes.Buffer
			err := kCtx.client.Resources().ExecInPod(ctx, namespace, pod, "agent", cmd, &stdout, &stderr)
			require.NoError(c, err, "failed to list the browser trust store: %s", stderr.String())
			got := 0
			for _, line := range strings.Split(stdout.String(), "\n") {
				// Nicknames of the CAs the agent imports start with custom-ca-.
				if strings.HasPrefix(line, "custom-ca-") {
					got++
				}
			}
			assert.Equal(c, want, got, "CAs in the browser trust store:\n%s", stdout.String())
		}, 4*time.Minute, 5*time.Second, msg)
	}
}

// k8sStepBrowserCAStoreOwner checks that, with the agent running as root, the browser
// trust store belongs to the user Heartbeat runs the browser as.
func k8sStepBrowserCAStoreOwner() k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		pod := browserCAAgentPod(t, ctx, kCtx, namespace)
		var stdout, stderr bytes.Buffer
		err := kCtx.client.Resources().ExecInPod(ctx, namespace, pod, "agent",
			[]string{"stat", "-c", "%U", browserAgentHome + "/.pki/nssdb/cert9.db"}, &stdout, &stderr)
		require.NoError(t, err, "failed to stat the browser trust store: %s", stderr.String())
		require.Equal(t, "elastic-agent", strings.TrimSpace(stdout.String()), "as root the trust store must belong to the browser user")
	}
}
