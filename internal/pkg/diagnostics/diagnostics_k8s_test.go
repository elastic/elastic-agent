// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package diagnostics

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	yamlk8s "sigs.k8s.io/yaml"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
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

func Test_dumpHelmRelease(t *testing.T) {
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
			manifestTmpFile := filepath.Join(tmpDir, "manifest.yaml")
			valuesTmpFile := filepath.Join(tmpDir, "values.yaml")
			_, _ = manifestTmpFile, valuesTmpFile
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
			err := dumpHelmRelease(t.Context(), clientSet, tc.agentPod, manifestTmpFile, valuesTmpFile)
			if tc.expectedErr {
				require.Error(t, err, "expected error in dumping helm chart values but got one")
				return
			}
			require.NoError(t, err, "expected no error in dumping helm chart values but got one")
			require.FileExists(t, valuesTmpFile, "expected values file to exist but it does not")
			require.FileExists(t, manifestTmpFile, "expected manifest file to exist but it does not")
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

func Test_dumpK8sManifests(t *testing.T) {

	type args struct {
		pod *corev1.Pod
	}
	tests := []struct {
		name          string
		args          args
		setupObjects  []runtime.Object
		wantErr       assert.ErrorAssertionFunc
		expectedFiles []string
	}{
		{
			name: "simple free-range pod, no owners",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "free-range-pod",
						Namespace: "namespace1",
					},
				},
			},
			setupObjects: nil,
			wantErr:      assert.NoError,
			expectedFiles: []string{
				"pod-free-range-pod.yaml",
			},
		},
		{
			name: "pod owned by replicaset and deployment",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "one-from-deployment",
						Namespace: "namespace1",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "apps/v1",
								Kind:       "ReplicaSet",
								Name:       "replicaset1",
							},
						},
					},
				},
			},
			setupObjects: []runtime.Object{
				&appsv1.ReplicaSet{
					TypeMeta: metav1.TypeMeta{
						Kind:       "ReplicaSet",
						APIVersion: "apps/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "replicaset1",
						Namespace: "namespace1",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "apps/v1",
								Kind:       "Deployment",
								Name:       "deployment1",
							},
						},
					},
				},
				&appsv1.Deployment{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Deployment",
						APIVersion: "apps/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "deployment1",
						Namespace: "namespace1",
					},
				},
			},
			wantErr: assert.NoError,
			expectedFiles: []string{
				"pod-one-from-deployment.yaml",
				"replicaset-replicaset1.yaml",
				"deployment-deployment1.yaml",
			},
		},
		{
			name: "pod owned by daemonset",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "one-from-daemon",
						Namespace: "namespace1",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "apps/v1",
								Kind:       "DaemonSet",
								Name:       "daemon1",
							},
						},
					},
				},
			},
			setupObjects: []runtime.Object{
				&appsv1.DaemonSet{
					TypeMeta: metav1.TypeMeta{
						Kind:       "DaemonSet",
						APIVersion: "apps/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "daemon1",
						Namespace: "namespace1",
					},
				},
			},
			wantErr: assert.NoError,
			expectedFiles: []string{
				"pod-one-from-daemon.yaml",
				"daemonset-daemon1.yaml",
			},
		},
		{
			name: "pod owned by statefulset",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "born-to-be-stateful-0",
						Namespace: "namespace1",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "apps/v1",
								Kind:       "StatefulSet",
								Name:       "born-to-be-stateful",
							},
						},
					},
				},
			},
			setupObjects: []runtime.Object{
				&appsv1.StatefulSet{
					TypeMeta: metav1.TypeMeta{
						Kind:       "StatefulSet",
						APIVersion: "apps/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "born-to-be-stateful",
						Namespace: "namespace1",
					},
				},
			},
			wantErr: assert.NoError,
			expectedFiles: []string{
				"pod-born-to-be-stateful-0.yaml",
				"statefulset-born-to-be-stateful.yaml",
			},
		},
		{
			name: "pod owner not found, we should get back an error",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-with-non-existing-owner",
						Namespace: "namespace1",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "v1",
								Kind:       "ReplicaSet",
								Name:       "non-existing-replicaset",
							},
						},
					},
				},
			},
			setupObjects: nil,
			wantErr:      assert.Error,
			expectedFiles: []string{
				"pod-pod-with-non-existing-owner.yaml",
			},
		},
		{
			name: "unsupported owner refs are skipped with error",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-with-a-job",
						Namespace: "namespace1",
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion: "batch/v1",
								Kind:       "Job",
								Name:       "jobber",
							},
						},
					},
				},
			},
			setupObjects: []runtime.Object{
				&batchv1.Job{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Job",
						APIVersion: "batch/v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "jobber",
						Namespace: "namespace1",
					},
				},
			},
			wantErr: assert.Error,
			expectedFiles: []string{
				"pod-pod-with-a-job.yaml",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sDir := t.TempDir()
			fakeClientset := k8sfake.NewClientset(tt.setupObjects...)
			tt.wantErr(t, dumpK8sManifests(t.Context(), fakeClientset, tt.args.pod, k8sDir), fmt.Sprintf("dumpK8sManifests(%v, %v, %v, %v)", t.Context(), fakeClientset, tt.args.pod, k8sDir))
			for _, ef := range tt.expectedFiles {
				assert.FileExists(t, filepath.Join(k8sDir, ef))
			}
		})
	}
}

func Test_collectLogsFromPod(t *testing.T) {
	type args struct {
		pod *corev1.Pod
	}
	tests := []struct {
		name          string
		args          args
		wantErr       assert.ErrorAssertionFunc
		expectedFiles []string
	}{
		{
			name: "single quiet elastic-agent container",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "namespace1",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "agent",
							},
						},
					},
					Status: corev1.PodStatus{
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name:         "agent",
								RestartCount: 0,
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
			expectedFiles: []string{
				"pod1-agent-current.log",
			},
		},
		{
			name: "one log file per container",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "namespace1",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "agent",
							},
							{
								Name: "sidecar",
							},
						},
					},
					Status: corev1.PodStatus{
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name:         "agent",
								RestartCount: 0,
							},
							{
								Name:         "sidecar",
								RestartCount: 0,
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
			expectedFiles: []string{
				"pod1-agent-current.log",
				"pod1-sidecar-current.log",
			},
		},
		{
			name: "restarted elastic-agent container will trigger collection of previous logs",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "namespace1",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "agent",
							},
							{
								Name: "sidecar",
							},
						},
					},
					Status: corev1.PodStatus{
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name:         "agent",
								RestartCount: 1,
							},
							{
								Name:         "sidecar",
								RestartCount: 0,
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
			expectedFiles: []string{
				"pod1-agent-current.log",
				"pod1-agent-previous.log",
				"pod1-sidecar-current.log",
			},
		},
		{
			name: "init containers will join the fun but not the previous ones",
			args: args{
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod1",
						Namespace: "namespace1",
					},
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Name: "init-agent",
							},
						},
						Containers: []corev1.Container{
							{
								Name: "agent",
							},
						},
					},
					Status: corev1.PodStatus{
						InitContainerStatuses: []corev1.ContainerStatus{
							{
								Name:         "init-agent",
								RestartCount: 1,
							},
						},
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name:         "agent",
								RestartCount: 1,
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
			expectedFiles: []string{
				"pod1-init-agent-current.log",
				"pod1-agent-current.log",
				"pod1-agent-previous.log",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logsDir := t.TempDir()
			fakeClientset := k8sfake.NewClientset()
			tt.wantErr(t, collectLogsFromPod(t.Context(), fakeClientset, tt.args.pod, logsDir), fmt.Sprintf("collectLogsFromPod(%v, %v, %v, %v)", t.Context(), fakeClientset, tt.args.pod, logsDir))
			for _, ef := range tt.expectedFiles {
				assert.FileExists(t, filepath.Join(logsDir, ef))
			}
		})
	}
}

func populateFakeCgroupDir(t *testing.T, dir string) {
	cGroupFiles := []string{
		"cgroup.controllers",
		"cgroup.events",
		"cgroup.freeze",
		"cgroup.kill",
		"cgroup.max.depth",
		"cgroup.max.descendants",
		"cgroup.pressure",
		"cgroup.procs",
		"cgroup.stat",
		"cgroup.subtree_control",
		"cgroup.threads",
		"cgroup.type",
		"cpu.idle",
		"cpu.max",
		"cpu.max.burst",
		"cpu.pressure",
		"cpu.stat",
		"cpu.stat.local",
		"cpu.uclamp.max",
		"cpu.uclamp.min",
		"cpu.weight",
		"cpu.weight.nice",
		"cpuset.cpus",
		"cpuset.cpus.effective",
		"cpuset.cpus.exclusive",
		"cpuset.cpus.exclusive.effective",
		"cpuset.cpus.partition",
		"cpuset.mems",
		"cpuset.mems.effective",
		"hugetlb.1GB.current",
		"hugetlb.1GB.events",
		"hugetlb.1GB.events.local",
		"hugetlb.1GB.max",
		"hugetlb.1GB.numa_stat",
		"hugetlb.1GB.rsvd.current",
		"hugetlb.1GB.rsvd.max",
		"hugetlb.2MB.current",
		"hugetlb.2MB.events",
		"hugetlb.2MB.events.local",
		"hugetlb.2MB.max",
		"hugetlb.2MB.numa_stat",
		"hugetlb.2MB.rsvd.current",
		"hugetlb.2MB.rsvd.max",
		"io.max",
		"io.pressure",
		"io.prio.class",
		"io.stat",
		"io.weight",
		"memory.current",
		"memory.events",
		"memory.events.local",
		"memory.high",
		"memory.low",
		"memory.max",
		"memory.min",
		"memory.numa_stat",
		"memory.oom.group",
		"memory.peak",
		"memory.pressure",
		"memory.reclaim",
		"memory.stat",
		"memory.swap.current",
		"memory.swap.events",
		"memory.swap.high",
		"memory.swap.max",
		"memory.swap.peak",
		"memory.zswap.current",
		"memory.zswap.max",
		"memory.zswap.writeback",
		"misc.current",
		"misc.events",
		"misc.events.local",
		"misc.max",
		"misc.peak",
		"pids.current",
		"pids.events",
		"pids.events.local",
		"pids.max",
		"pids.peak",
		"rdma.current",
		"rdma.max",
	}

	for _, f := range cGroupFiles {
		create, err := os.Create(filepath.Join(dir, f))
		require.NoErrorf(t, err, "error creating fake cgroup file %s", f)
		err = create.Close()
		require.NoErrorf(t, err, "error closing fake cgroup file %s", f)
	}
}

func Test_collectCgroup(t *testing.T) {
	tests := []struct {
		name           string
		setupCgroupDir func(t *testing.T, cgroupDir string)
		wantErr        assert.ErrorAssertionFunc
		wantFiles      []string
	}{
		{
			name:           "empty cgroup directory will cause an error",
			setupCgroupDir: nil, // nothing to do here
			wantErr:        assert.Error,
			wantFiles:      []string{},
		},
		{
			name:           "collect memory events from fully-populated cgroup directory",
			setupCgroupDir: populateFakeCgroupDir,
			wantErr:        assert.NoError,
			wantFiles: []string{
				"memory.events",
				"memory.stat",
				"memory.low",
				"memory.high",
				"memory.min",
				"memory.max",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			cgroupDir := t.TempDir()
			if tt.setupCgroupDir != nil {
				tt.setupCgroupDir(t, cgroupDir)
			}
			outputDir := t.TempDir()
			tt.wantErr(t, collectCgroup(t.Context(), cgroupDir, outputDir), fmt.Sprintf("collectCgroup(%v, %v, %v)", t.Context(), cgroupDir, outputDir))
			for _, file := range tt.wantFiles {
				assert.FileExists(t, filepath.Join(outputDir, file))
			}
		})
	}
}

func Test_collectK8sDiagnosticsWithClientAndToken(t *testing.T) {
	type args struct {
		namespace string
		podName   string
	}
	tests := []struct {
		name       string
		k8sObjects []runtime.Object
		args       args
		assertFunc func(t *testing.T, actual []byte)
	}{
		{
			name:       "pod does not exist, will return a zip with an error file",
			k8sObjects: nil,
			args: args{
				namespace: "default",
				podName:   "nonexistingpod",
			},
			assertFunc: func(t *testing.T, actual []byte) {
				reader := bytes.NewReader(actual)
				tempAssertDir := t.TempDir()
				err := extractZipArchive(reader, tempAssertDir)
				require.NoError(t, err)
				assert.FileExists(t, filepath.Join(tempAssertDir, K8sDiagnosticsErrorFile), "k8s diagnostics should contain an error file")
				assert.NoDirExists(t, filepath.Join(tempAssertDir, K8sSubdir))
			},
		},
		{
			name: "simple pod",
			k8sObjects: []runtime.Object{
				&corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "simplepod",
						Namespace: "namespace1",
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "agent",
							},
						},
					},
					Status: corev1.PodStatus{},
				},
			},
			args: args{
				namespace: "namespace1",
				podName:   "simplepod",
			},
			assertFunc: func(t *testing.T, actual []byte) {
				reader := bytes.NewReader(actual)
				tempAssertDir := t.TempDir()
				err := extractZipArchive(reader, tempAssertDir)
				require.NoError(t, err)
				// Some cgroup stuff will fail so we still have a diag-errors.txt file
				assert.FileExists(t, filepath.Join(tempAssertDir, K8sDiagnosticsErrorFile), "k8s diagnostics should contain an error file")
				// We have at least the pod manifest
				assert.DirExists(t, filepath.Join(tempAssertDir, K8sSubdir))
				assert.FileExists(t, filepath.Join(tempAssertDir, K8sSubdir, fmt.Sprintf(PodK8sManifestFormat, "simplepod")))
				// We have the fake logs for the agent container
				assert.DirExists(t, filepath.Join(tempAssertDir, K8sSubdir, logsSubDir))
				assert.FileExists(t, filepath.Join(tempAssertDir, K8sSubdir, logsSubDir, fmt.Sprintf(CurrentLogFileFormat, "simplepod", "agent")))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, _ := loggertest.New(t.Name())
			k8sClient := k8sfake.NewClientset(tt.k8sObjects...)
			tmpDir := t.TempDir()
			actualBytes := collectK8sDiagnosticsWithClientAndToken(t.Context(), logger, k8sClient, tt.args.namespace, tt.args.podName, tmpDir)
			require.NotEmpty(t, actualBytes, "returned bytes should not be empty")
			tt.assertFunc(t, actualBytes)
		})
	}
}

func extractZipArchive(reader *bytes.Reader, outputDir string) error {
	newReader, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return fmt.Errorf("bytes do not look like a .zip file: %w", err)
	}

	for _, f := range newReader.File {

		if f.FileInfo().IsDir() {
			err = os.MkdirAll(f.Name, f.FileInfo().Mode())
			if err != nil {
				return fmt.Errorf("error creating dir %q: %w", f.Name, err)
			}
			continue
		}

		outputFile := filepath.Join(outputDir, f.Name)
		containingDir := path.Dir(outputFile)
		err = os.MkdirAll(containingDir, 0755)
		if err != nil {
			return fmt.Errorf("error creating output dir %q: %w", containingDir, err)
		}

		err = extractFile(f, outputFile)
		if err != nil {
			return fmt.Errorf("error extracting file %q to %q: %w", f.Name, outputFile, err)
		}
	}

	return nil
}

func extractFile(f *zip.File, outputFile string) error {
	fileReader, err := f.Open()
	if err != nil {
		return fmt.Errorf("error reading file %q: %w", f.Name, err)
	}
	defer fileReader.Close()

	fileWriter, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file %q: %w", outputFile, err)
	}
	defer fileWriter.Close()

	_, err = io.Copy(fileWriter, fileReader)
	if err != nil {
		return fmt.Errorf("error copying file %q to %q: %w", f.Name, outputFile, err)
	}
	return nil
}
