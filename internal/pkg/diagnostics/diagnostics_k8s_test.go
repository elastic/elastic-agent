// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package diagnostics

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	yamlk8s "sigs.k8s.io/yaml"
)

func Test_readServiceAccountToken(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		serviceAccountTokenContent []byte
		expectedPayload            *TokenPayload
		expectedErr                bool
	}{
		{
			name:                       "should succeed",
			serviceAccountTokenContent: []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9nM1dvSVFqQjdyR1JjVXNTdHI1N2c4UDNJODBuYTNGaDdrWTAzRlJUSDAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzg0NjQ1Nzg4LCJpYXQiOjE3NTMxMDk3ODgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInBvZCI6eyJuYW1lIjoiYWdlbnQtcGVybm9kZS1lbGFzdGljLWFnZW50LWJqOHpjIiwidWlkIjoiZWFkNGYwMWYtMTUzMi00ZTM2LWI5N2MtMThiOTYwOWIyODhjIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhZ2VudC1wZXJub2RlLWVsYXN0aWMtYWdlbnQiLCJ1aWQiOiIxYzU3NTA3My1hMDI0LTRmMGItYTdlNi1kMzBmNDY1NmE2N2UifSwid2FybmFmdGVyIjoxNzUzMTEzMzk1fSwibmJmIjoxNzUzMTA5Nzg4LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06YWdlbnQtcGVybm9kZS1lbGFzdGljLWFnZW50In0.ARUU__Ha5-O-w6xokpiuBiK0I4KZsGZQDrYUl0ngVieDMWX7huk2SgBc7a94rhmNkrexiX86LU11EMOHJY-1szsnoLULKHYRwZp0t6LW1AcPOK5ysX-_hOfPmYUE8BmX5lJOuPZTrHjiSaOhtXB2Q_tuDPL_uHPCrLRruXKIygWg-9fxK_d8mfLqFPt_oxfBJyt7ODW8PtWdChVfAv-b4m4aD1357CJPrjVqegqSqZplU7KrLDBgLtohefoEEohPYRRo8M_vZsfkqUzfg5UjN81teGE61zaApwhua3OHFQ01m2XQDoU4oQbx4WznRsoddPeADeVpsSU76VnWCPDisw`),
			expectedPayload: &TokenPayload{
				Namespace: "kube-system",
				Pod: PodInfoToken{
					Name: "agent-pernode-elastic-agent-bj8zc",
					UID:  "ead4f01f-1532-4e36-b97c-18b9609b288c",
				},
				ServiceAccount: ServiceAccountInfoToken{
					Name: "agent-pernode-elastic-agent",
					UID:  "1c575073-a024-4f0b-a7e6-d30f4656a67e",
				},
			},
			expectedErr: false,
		},
		{
			name:                       "should fail because of less jwt parts",
			serviceAccountTokenContent: []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9nM1dvSVFqQjdyR1JjVXNTdHI1N2c4UDNJODBuYTNGaDdrWTAzRlJUSDAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzg0NjQ1Nzg4LCJpYXQiOjE3NTMxMDk3ODgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInBvZCI6eyJuYW1lIjoiYWdlbnQtcGVybm9kZS1lbGFzdGljLWFnZW50LWJqOHpjIiwidWlkIjoiZWFkNGYwMWYtMTUzMi00ZTM2LWI5N2MtMThiOTYwOWIyODhjIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhZ2VudC1wZXJub2RlLWVsYXN0aWMtYWdlbnQiLCJ1aWQiOiIxYzU3NTA3My1hMDI0LTRmMGItYTdlNi1kMzBmNDY1NmE2N2UifSwid2FybmFmdGVyIjoxNzUzMTEzMzk1fSwibmJmIjoxNzUzMTA5Nzg4LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06YWdlbnQtcGVybm9kZS1lbGFzdGljLWFnZW50In0`),
			expectedPayload:            nil,
			expectedErr:                true,
		},
		{
			name:                       "should fail because of missing token file",
			serviceAccountTokenContent: nil,
			expectedPayload:            nil,
			expectedErr:                true,
		},
		{
			name:                       "should fail because of invalid base64 payload",
			serviceAccountTokenContent: []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9nM1dvSVFqQjdyR1JjVXNTdHI1N2c4UDNJODBuYTNGaDdrWTAzRlJUSDAifQ.SGVsbG8gd29ybGQ!@.ARUU__Ha5-O-w6xokpiuBiK0I4KZsGZQDrYUl0ngVieDMWX7huk2SgBc7a94rhmNkrexiX86LU11EMOHJY-1szsnoLULKHYRwZp0t6LW1AcPOK5ysX-_hOfPmYUE8BmX5lJOuPZTrHjiSaOhtXB2Q_tuDPL_uHPCrLRruXKIygWg-9fxK_d8mfLqFPt_oxfBJyt7ODW8PtWdChVfAv-b4m4aD1357CJPrjVqegqSqZplU7KrLDBgLtohefoEEohPYRRo8M_vZsfkqUzfg5UjN81teGE61zaApwhua3OHFQ01m2XQDoU4oQbx4WznRsoddPeADeVpsSU76VnWCPDisw`),
			expectedPayload:            nil,
			expectedErr:                true,
		},
		{
			name:                       "should fail because of invalid json",
			serviceAccountTokenContent: []byte(`eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9nM1dvSVFqQjdyR1JjVXNTdHI1N2c4UDNJODBuYTNGaDdrWTAzRlJUSDAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5xNzg0NjQ1Nzg4LCJpYXQiOjE3NTMxMDk3ODgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHV.ARUU__Ha5-O-w6xokpiuBiK0I4KZsGZQDrYUl0ngVieDMWX7huk2SgBc7a94rhmNkrexiX86LU11EMOHJY-1szsnoLULKHYRwZp0t6LW1AcPOK5ysX-_hOfPmYUE8BmX5lJOuPZTrHjiSaOhtXB2Q_tuDPL_uHPCrLRruXKIygWg-9fxK_d8mfLqFPt_oxfBJyt7ODW8PtWdChVfAv-b4m4aD1357CJPrjVqegqSqZplU7KrLDBgLtohefoEEohPYRRo8M_vZsfkqUzfg5UjN81teGE61zaApwhua3OHFQ01m2XQDoU4oQbx4WznRsoddPeADeVpsSU76VnWCPDisw`),
			expectedPayload:            nil,
			expectedErr:                true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "testfile")

			if len(tc.serviceAccountTokenContent) > 0 {
				err := os.WriteFile(tmpFile, tc.serviceAccountTokenContent, 0600)
				require.NoError(t, err, "failed to write service account file ", tmpFile)
			}

			payload, err := readServiceAccountToken(tmpFile)
			if tc.expectedErr {
				require.Error(t, err, "expected error but got none")
				require.Nil(t, payload)
			} else {
				require.NoError(t, err, "expected no error but got one")
				require.Equal(t, tc.expectedPayload, payload)
			}
		})
	}
}

func Test_writeNamespaceLeases(t *testing.T) {
	for _, tc := range []struct {
		name           string
		namespace      string
		leases         []v1.Lease
		expectedOutput string
		expectedErr    bool
	}{
		{
			name:      "should write leases to a file",
			namespace: "namespace1",
			leases: []v1.Lease{
				{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Lease",
						APIVersion: "coordination.k8s.io/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "lease1",
						Namespace: "namespace1",
					},
					Spec: v1.LeaseSpec{
						HolderIdentity:       ptrOf("holder1"),
						LeaseDurationSeconds: nil,
						AcquireTime:          nil,
						RenewTime:            nil,
						LeaseTransitions:     nil,
						Strategy:             ptrOf(v1.OldestEmulationVersion),
						PreferredHolder:      ptrOf("holder1"),
					},
				},
			},
		},
		{
			name:      "should not write leases because namespace does not match",
			namespace: "namespace2",
			leases: []v1.Lease{
				{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Lease",
						APIVersion: "coordination.k8s.io/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "lease1",
						Namespace: "namespace1",
					},
					Spec: v1.LeaseSpec{
						HolderIdentity:       ptrOf("holder1"),
						LeaseDurationSeconds: nil,
						AcquireTime:          nil,
						RenewTime:            nil,
						LeaseTransitions:     nil,
						Strategy:             ptrOf(v1.OldestEmulationVersion),
						PreferredHolder:      ptrOf("holder1"),
					},
				},
			},
		},
		{
			name:      "should not write leases because there are no leases",
			namespace: "namespace1",
			leases:    []v1.Lease{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "leases.yaml")
			var objs []runtime.Object
			compareMap := make(map[string]*v1.Lease)
			for _, lease := range tc.leases {
				objs = append(objs, &lease)

				if lease.Namespace != tc.namespace {
					continue
				}
				id := fmt.Sprintf("%s/%s", lease.Namespace, lease.Name)
				compareMap[id] = &lease
			}
			clientSet := k8sfake.NewClientset(objs...)

			err := writeNamespaceLeases(t.Context(), clientSet, tc.namespace, tmpFile)
			if tc.expectedErr {
				require.Error(t, err, "expected error in writing leases but got one")
				return
			}
			if len(compareMap) == 0 {
				require.NoFileExists(t, tmpFile)
				return
			}
			require.NoError(t, err, "expected no error in writing leases but got one")
			leasesBytes, err := os.ReadFile(tmpFile)
			require.NoError(t, err, "expected no error in reading leases but got one")
			var writtenLeases []v1.Lease
			err = yamlk8s.Unmarshal(leasesBytes, &writtenLeases)
			require.NoError(t, err, "expected no error in unmarshalling leases but got one")
			for _, lease := range writtenLeases {
				id := fmt.Sprintf("%s/%s", lease.Namespace, lease.Name)
				existingLease, ok := compareMap[id]
				require.True(t, ok, "unexpected lease %s", id)
				require.EqualValues(t, existingLease.Spec, lease.Spec)
			}
		})
	}
}

func Test_dumpHelmChartValues(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		agentPod                   *corev1.Pod
		secrets                    []*corev1.Secret
		releaseSecretsDataFilePath map[string]string
		expectedErr                bool
	}{
		{
			name: "should read the values file",
			agentPod: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "namespace1",
					Labels: map[string]string{
						"helm.sh/chart":              "elastic-agent-test",
						"app.kubernetes.io/instance": "release1",
					},
				},
			},
			secrets: []*corev1.Secret{
				{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Secret",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "secret1",
						Namespace: "namespace1",
						Labels: map[string]string{
							"owner":  "helm",
							"name":   "release1",
							"status": "deployed",
						},
					},
					Data: map[string][]byte{
						"release": nil, // filled by releaseSecretsDataFilePath
					},
				},
			},
			releaseSecretsDataFilePath: map[string]string{
				"namespace1/secret1": "testdata/helm.release.v1.secret.data",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			chartArchiveTmpFile := filepath.Join(tmpDir, "chart")
			valuesTmpFile := filepath.Join(tmpDir, "chart", "values.yaml")
			_, _ = chartArchiveTmpFile, valuesTmpFile
			var objs []runtime.Object
			for _, secret := range tc.secrets {
				id := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
				if filePath, ok := tc.releaseSecretsDataFilePath[id]; ok {
					var err error
					secret.Data["release"], err = readSecretDataFromFile(filePath)
					require.NoError(t, err, "expected no error in reading secret data file but got one")
				}
				objs = append(objs, secret)
			}

			clientSet := k8sfake.NewClientset(objs...)
			err := dumpHelmChartValues(t.Context(), clientSet, tc.agentPod, chartArchiveTmpFile, valuesTmpFile)
			if tc.expectedErr {
				require.Error(t, err, "expected error in dumping helm chart values but got one")
				return
			}
			require.NoError(t, err, "expected no error in dumping helm chart values but got one")
			require.FileExists(t, valuesTmpFile, "expected values file to exist but it does not")
		})
	}
}

func readSecretDataFromFile(filePath string) ([]byte, error) {
	secretData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(string(secretData))
}

func ptrOf[T any](s T) *T {
	return &s
}

func Test_dumpK8sEvents(t *testing.T) {
	for _, tc := range []struct {
		name        string
		namespace   string
		agentPod    *corev1.Pod
		events      []corev1.Event
		expectedErr bool
	}{
		{
			name:      "should dump k8s events",
			namespace: "namespace1",
			agentPod: &corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod1",
					Namespace: "namespace1",
				},
			},
			events: []corev1.Event{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "event1",
						Namespace: "namespace1",
					},
					InvolvedObject: corev1.ObjectReference{
						Name:      "pod1",
						Namespace: "namespace1",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			eventsTmpFile := filepath.Join(tmpDir, "events.yaml")
			var objs []runtime.Object
			for _, event := range tc.events {
				objs = append(objs, &event)
			}
			clientSet := k8sfake.NewClientset(objs...)
			err := dumpK8sEvents(t.Context(), clientSet, tc.agentPod, eventsTmpFile)
			if tc.expectedErr {
				require.Error(t, err, "expected error in dumping k8s events but got one")
				return
			}
			require.NoError(t, err, "expected no error in dumping k8s events but got one")
			require.FileExists(t, eventsTmpFile, "expected events file to exist but it does not")
		})
	}
}
