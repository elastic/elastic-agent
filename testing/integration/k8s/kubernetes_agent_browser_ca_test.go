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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/e2e-framework/klient/k8s"

	"github.com/elastic/elastic-agent/pkg/testing/define"
)

const (
	browserCASecret   = "browser-ca"
	browserCAServer   = "tls-server"
	browserAgentHome  = "/usr/share/elastic-agent"
	browserCAPodLabel = "name=agent-clusterwide-helm-agent"
)

// TestKubernetesAgentBrowserTrustsMountedCA installs the chart with a complete image and a
// CA Secret, then runs a browser journey in the agent pod against an HTTPS server that CA
// signed. Adding the CA to the Secret must make the browser trust the server, and removing
// it must make the browser reject it again, without restarting the agent.
func TestKubernetesAgentBrowserTrustsMountedCA(t *testing.T) {
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

	for _, unprivileged := range []bool{false, true} {
		t.Run(fmt.Sprintf("unprivileged=%t", unprivileged), func(t *testing.T) {
			testNamespace := kCtx.getNamespace(t)
			caPEM, certPEM, keyPEM := browserCATestCertificates(t, testNamespace)
			steps := []k8sTestStep{
				k8sStepCreateNamespace(),
				k8sStepBrowserCACreateObjects(certPEM, keyPEM),
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
								"resources": map[string]any{
									"limits": map[string]any{"memory": "1500Mi"},
								},
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
				k8sStepBrowserJourney(unprivileged, "failed", "without the CA the browser must reject the server's certificate, or this test proves nothing"),
				k8sStepBrowserCASetSecret(map[string][]byte{"ca.crt": caPEM}),
				k8sStepBrowserJourney(unprivileged, "succeeded", "a CA added to the Secret must be trusted by the browser without a restart"),
				k8sStepBrowserCASetSecret(map[string][]byte{}),
				k8sStepBrowserJourney(unprivileged, "failed", "a CA removed from the Secret must stop being trusted without a restart"),
			}

			for _, step := range steps {
				step(t, ctx, kCtx, testNamespace)
			}
		})
	}
}

// browserCATestCertificates returns a CA and a server certificate and key it signed for
// the test server's Service in namespace, all in PEM form.
func browserCATestCertificates(t *testing.T, namespace string) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating CA key")
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "elastic-agent browser CA test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err, "creating CA")
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err, "parsing CA")

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generating server key")
	srvDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: browserCAServer},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{browserCAServerHost(namespace)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, caCert, &srvKey.PublicKey, caKey)
	require.NoError(t, err, "creating server certificate")
	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	require.NoError(t, err, "encoding server key")

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func browserCAServerHost(namespace string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", browserCAServer, namespace)
}

// k8sStepBrowserCACreateObjects creates the CA Secret, still empty, and an nginx server
// that serves HTTPS with the given certificate.
func k8sStepBrowserCACreateObjects(certPEM, keyPEM []byte) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		labels := map[string]string{"app": browserCAServer}
		replicas := int32(1)
		objects := []k8s.Object{
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: browserCASecret},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: browserCAServer},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{corev1.TLSCertKey: certPEM, corev1.TLSPrivateKeyKey: keyPEM},
			},
			&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: browserCAServer},
				Data: map[string]string{"default.conf": `server {
  listen 8443 ssl;
  ssl_certificate /etc/nginx/tls/tls.crt;
  ssl_certificate_key /etc/nginx/tls/tls.key;
  location / {
    default_type text/html;
    return 200 '<html><title>ok</title></html>';
  }
}
`},
			},
			&appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: browserCAServer},
				Spec: appsv1.DeploymentSpec{
					Replicas: &replicas,
					Selector: &metav1.LabelSelector{MatchLabels: labels},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{Labels: labels},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{
								Name:  "nginx",
								Image: "docker.io/library/nginx:1.27-alpine",
								Ports: []corev1.ContainerPort{{ContainerPort: 8443}},
								VolumeMounts: []corev1.VolumeMount{
									{Name: "conf", MountPath: "/etc/nginx/conf.d", ReadOnly: true},
									{Name: "tls", MountPath: "/etc/nginx/tls", ReadOnly: true},
								},
							}},
							Volumes: []corev1.Volume{
								{Name: "conf", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: browserCAServer},
								}}},
								{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
									SecretName: browserCAServer,
								}}},
							},
						},
					},
				},
			},
			&corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: browserCAServer},
				Spec: corev1.ServiceSpec{
					Selector: labels,
					Ports:    []corev1.ServicePort{{Port: 443, TargetPort: intstr.FromInt32(8443)}},
				},
			},
		}

		err := k8sCreateObjects(ctx, kCtx.client, k8sCreateOpts{wait: true, namespace: namespace}, objects...)
		require.NoError(t, err, "failed to create the CA Secret and the HTTPS server")
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

// k8sStepBrowserJourney runs a one-step browser journey that opens the HTTPS server from
// the agent pod until it ends with wantStatus ("succeeded" or "failed"). Updated Secrets
// reach the pod after the kubelet's sync period, hence the long wait.
func k8sStepBrowserJourney(unprivileged bool, wantStatus, msg string) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		pods := &corev1.PodList{}
		err := kCtx.client.Resources(namespace).List(ctx, pods, func(opt *metav1.ListOptions) {
			opt.LabelSelector = browserCAPodLabel
		})
		require.NoError(t, err, "failed to list the agent pods")
		require.Len(t, pods.Items, 1, "expected one clusterWide agent pod")
		pod := pods.Items[0].Name

		// As root, Heartbeat runs the browser as the agent user with that user's home:
		// do the same. Otherwise the browser uses the pod's HOME, as the agent does.
		env := ""
		if !unprivileged {
			env = "HOME=" + browserAgentHome + " "
		}
		script := fmt.Sprintf(`step("load", async () => { await page.goto("https://%s"); });`, browserCAServerHost(namespace))
		cmd := []string{"sh", "-c", fmt.Sprintf(
			"cd /tmp && printf '%%s' '%s' | %selastic-synthetics --inline --reporter json --no-throttling",
			script, env)}

		var lastOutput string
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var stdout, stderr bytes.Buffer
			execCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			// A failed journey exits non-zero: its status is in the output.
			_ = kCtx.client.Resources().ExecInPod(execCtx, namespace, pod, "agent", cmd, &stdout, &stderr)
			lastOutput = stdout.String() + stderr.String()
			assert.Equal(c, wantStatus, journeyEndStatus(stdout.String()), "journey status")
		}, 5*time.Minute, 5*time.Second, "%s; last output:\n%s", msg, lastOutput)

		if !unprivileged {
			var stdout, stderr bytes.Buffer
			err := kCtx.client.Resources().ExecInPod(ctx, namespace, pod, "agent",
				[]string{"stat", "-c", "%U", browserAgentHome + "/.pki/nssdb/cert9.db"}, &stdout, &stderr)
			require.NoError(t, err, "failed to stat the browser trust store: %s", stderr.String())
			require.Equal(t, "elastic-agent", strings.TrimSpace(stdout.String()), "as root the trust store must belong to the browser user")
		}
	}
}

// journeyEndStatus returns the status of the journey/end event in the JSON output of
// elastic-synthetics, or "" when there is none.
func journeyEndStatus(output string) string {
	for _, line := range strings.Split(output, "\n") {
		var ev struct {
			Type    string `json:"type"`
			Journey struct {
				Status string `json:"status"`
			} `json:"journey"`
		}
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Type == "journey/end" {
			return ev.Journey.Status
		}
	}
	return ""
}
