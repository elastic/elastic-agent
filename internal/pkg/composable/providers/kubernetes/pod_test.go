// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"context"
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/pkg/core/logger"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-autodiscover/kubernetes/metadata"
	"github.com/elastic/elastic-agent-libs/mapstr"

	c "github.com/elastic/elastic-agent-libs/config"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func getLogger() *logger.Logger {
	loggerCfg := logger.DefaultLoggingConfig()
	loggerCfg.Level = logp.ErrorLevel

	eventLoggerCfg := logger.DefaultEventLoggingConfig()
	eventLoggerCfg.Level = loggerCfg.Level

	l, _ := logger.NewFromConfig("", loggerCfg, eventLoggerCfg, false)
	return l
}

func TestGeneratePodData(t *testing.T) {
	pod := &kubernetes.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testpod",
			UID:       types.UID(uid),
			Namespace: "testns",
			Labels: map[string]string{
				"foo":        "bar",
				"with-dash":  "dash-value",
				"with/slash": "some/path",
			},
			Annotations: map[string]string{
				"app": "production",
			},
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		Spec: kubernetes.PodSpec{
			NodeName: "testnode",
		},
		Status: kubernetes.PodStatus{PodIP: "127.0.0.5"},
	}

	namespaceAnnotations := mapstr.M{
		"nsa": "nsb",
	}
	data := generatePodData(pod, &podMeta{}, namespaceAnnotations)

	mapping := map[string]interface{}{
		"namespace": pod.GetNamespace(),
		"pod": mapstr.M{
			"uid":  string(pod.GetUID()),
			"name": pod.GetName(),
			"ip":   pod.Status.PodIP,
		},
		"namespace_annotations": mapstr.M{
			"nsa": "nsb",
		},
		"labels": mapstr.M{
			"foo":        "bar",
			"with-dash":  "dash-value",
			"with/slash": "some/path",
		},
		"annotations": mapstr.M{
			"app": "production",
		},
	}

	processors := map[string]interface{}{
		"orchestrator": mapstr.M{
			"cluster": mapstr.M{
				"name": "devcluster",
				"url":  "8.8.8.8:9090"},
		}, "kubernetes": mapstr.M{
			"namespace": "testns",
			"labels": mapstr.M{
				"foo":        "bar",
				"with-dash":  "dash-value",
				"with/slash": "some/path",
			},
			"annotations": mapstr.M{"app": "production"},
			"pod": mapstr.M{
				"ip":   "127.0.0.5",
				"name": "testpod",
				"uid":  uid}},
	}
	assert.Equal(t, string(pod.GetUID()), data.uid)
	assert.Equal(t, mapping, data.mapping)
	for _, v := range data.processors {
		k, _ := v["add_fields"].(map[string]interface{})
		target, _ := k["target"].(string)
		fields := k["fields"]
		assert.Equal(t, processors[target], fields)
	}
}

func TestGenerateContainerPodData(t *testing.T) {
	containers := []kubernetes.Container{
		{
			Name:  "nginx",
			Image: "nginx:1.120",
			Ports: []kubernetes.ContainerPort{
				{
					Name:          "http",
					Protocol:      v1.ProtocolTCP,
					ContainerPort: 80,
				},
			},
		},
	}
	containerStatuses := []kubernetes.PodContainerStatus{
		{
			Name:        "nginx",
			Ready:       true,
			ContainerID: "crio://asdfghdeadbeef",
		},
	}
	pod := &kubernetes.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testpod",
			UID:       types.UID(uid),
			Namespace: "testns",
			Labels: map[string]string{
				"foo":        "bar",
				"with-dash":  "dash-value",
				"with/slash": "some/path",
			},
			Annotations: map[string]string{
				"app": "production",
			},
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		Spec: kubernetes.PodSpec{
			NodeName:   "testnode",
			Containers: containers,
		},
		Status: kubernetes.PodStatus{
			PodIP:             "127.0.0.5",
			ContainerStatuses: containerStatuses,
		},
	}

	providerDataChan := make(chan providerData, 1)

	comm := MockDynamicComm{
		context.TODO(),
		providerDataChan,
	}
	logger := getLogger()
	var cfg Config
	c := config.New()
	_ = c.Unpack(&cfg)
	generateContainerData(
		&comm,
		pod,
		&podMeta{},
		mapstr.M{
			"nsa": "nsb",
		},
		logger,
		true,
		&cfg,
	)

	mapping := map[string]interface{}{
		"namespace": pod.GetNamespace(),
		"pod": mapstr.M{
			"uid":  string(pod.GetUID()),
			"name": pod.GetName(),
			"ip":   pod.Status.PodIP,
		},
		"container": mapstr.M{
			"id":        "asdfghdeadbeef",
			"name":      "nginx",
			"image":     "nginx:1.120",
			"runtime":   "crio",
			"port":      "80",
			"port_name": "http",
		},
		"namespace_annotations": mapstr.M{
			"nsa": "nsb",
		},
		"annotations": mapstr.M{
			"app": "production",
		},
		"labels": mapstr.M{
			"foo":        "bar",
			"with-dash":  "dash-value",
			"with/slash": "some/path",
		},
	}

	processors := map[string]interface{}{
		"container": mapstr.M{
			"id":      "asdfghdeadbeef",
			"image":   mapstr.M{"name": "nginx:1.120"},
			"runtime": "crio",
		}, "orchestrator": mapstr.M{
			"cluster": mapstr.M{
				"name": "devcluster",
				"url":  "8.8.8.8:9090"},
		}, "kubernetes": mapstr.M{
			"namespace":   "testns",
			"annotations": mapstr.M{"app": "production"},
			"labels": mapstr.M{
				"foo":        "bar",
				"with-dash":  "dash-value",
				"with/slash": "some/path",
			},
			"pod": mapstr.M{
				"ip":   "127.0.0.5",
				"name": "testpod",
				"uid":  uid}},
	}
	cuid := fmt.Sprintf("%s.%s", pod.GetObjectMeta().GetUID(), "nginx")
	data := <-providerDataChan
	assert.Equal(t, cuid, data.uid)
	assert.Equal(t, mapping, data.mapping)
	for _, v := range data.processors {
		k, _ := v["add_fields"].(map[string]interface{})
		target, _ := k["target"].(string)
		fields := k["fields"]
		assert.Equal(t, processors[target], fields)
	}

}

func TestEphemeralContainers(t *testing.T) {
	containers := []v1.EphemeralContainer{
		{
			EphemeralContainerCommon: v1.EphemeralContainerCommon{
				Image: "nginx:1.120",
				Name:  "nginx",
			},
		},
	}
	containerStatuses := []kubernetes.PodContainerStatus{
		{
			Name:        "nginx",
			Ready:       true,
			ContainerID: "crio://asdfghdeadbeef",
		},
	}
	pod := &kubernetes.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testpod",
			UID:       types.UID(uid),
			Namespace: "testns",
			Labels: map[string]string{
				"foo":        "bar",
				"with-dash":  "dash-value",
				"with/slash": "some/path",
			},
			Annotations: map[string]string{
				"app": "production",
			},
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		Spec: kubernetes.PodSpec{
			NodeName:            "testnode",
			EphemeralContainers: containers,
		},
		Status: kubernetes.PodStatus{
			PodIP:                      "127.0.0.5",
			EphemeralContainerStatuses: containerStatuses,
		},
	}

	providerDataChan := make(chan providerData, 1)

	comm := MockDynamicComm{
		context.TODO(),
		providerDataChan,
	}

	logger := getLogger()
	var cfg Config
	c := config.New()
	_ = c.Unpack(&cfg)
	generateContainerData(
		&comm,
		pod,
		&podMeta{},
		mapstr.M{
			"nsa": "nsb",
		},
		logger,
		true,
		&cfg)

	mapping := map[string]interface{}{
		"namespace": pod.GetNamespace(),
		"pod": mapstr.M{
			"uid":  string(pod.GetUID()),
			"name": pod.GetName(),
			"ip":   pod.Status.PodIP,
		},
		"labels": mapstr.M{
			"foo":        "bar",
			"with-dash":  "dash-value",
			"with/slash": "some/path",
		},
		"container": mapstr.M{
			"id":      "asdfghdeadbeef",
			"name":    "nginx",
			"image":   "nginx:1.120",
			"runtime": "crio",
		},
		"namespace_annotations": mapstr.M{
			"nsa": "nsb",
		},
		"annotations": mapstr.M{
			"app": "production",
		},
	}

	processors := map[string]interface{}{
		"container": mapstr.M{
			"id":      "asdfghdeadbeef",
			"image":   mapstr.M{"name": "nginx:1.120"},
			"runtime": "crio",
		}, "orchestrator": mapstr.M{
			"cluster": mapstr.M{
				"name": "devcluster",
				"url":  "8.8.8.8:9090"},
		}, "kubernetes": mapstr.M{
			"namespace": "testns",
			"labels": mapstr.M{
				"foo":        "bar",
				"with-dash":  "dash-value",
				"with/slash": "some/path",
			},
			"annotations": mapstr.M{"app": "production"},
			"pod": mapstr.M{
				"ip":   "127.0.0.5",
				"name": "testpod",
				"uid":  uid}},
	}
	cuid := fmt.Sprintf("%s.%s", pod.GetObjectMeta().GetUID(), "nginx")
	data := <-providerDataChan
	assert.Equal(t, cuid, data.uid)
	assert.Equal(t, mapping, data.mapping)
	for _, v := range data.processors {
		k, _ := v["add_fields"].(map[string]interface{})
		target, _ := k["target"].(string)
		fields := k["fields"]
		assert.Equal(t, processors[target], fields)
	}

}

func TestGenerateHints(t *testing.T) {
	pod := &kubernetes.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testpod",
			UID:       types.UID(uid),
			Namespace: "testns",
			Labels: map[string]string{
				"foo": "bar",
			},
			Annotations: map[string]string{
				"app":                                "production",
				"co.elastic.hints/host":              "${kubernetes.pod.ip}:6379",
				"co.elastic.hints/package":           "redis",
				"co.elastic.hints/metricssssssspath": "/metrics",
				"co.elastic.hints/period":            "42s",
			},
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		Spec: kubernetes.PodSpec{
			NodeName: "testnode",
		},
		Status: kubernetes.PodStatus{PodIP: "127.0.0.5"},
	}

	data := generatePodData(pod, &podMeta{}, mapstr.M{})

	hints_result := mapstr.M{
		"hints": mapstr.M{
			"host":              "${kubernetes.pod.ip}:6379",
			"package":           "redis",
			"metricssssssspath": "/metrics", // on purpose we have introduced a typo
			"period":            "42s",
		},
	}
	incorrecthints_results := []string{"hints/metricssssssspath"}

	ann := data.mapping["annotations"]
	annotations, _ := ann.(mapstr.M)
	prefix := "co.elastic"

	log, err := logger.New("hint-test", true)
	assert.NoError(t, err)

	hints, incorrecthints := hintsCheck(annotations, "", prefix, true, allSupportedHints, log, pod)

	assert.Equal(t, string(pod.GetUID()), data.uid)
	assert.Equal(t, hints, hints_result)
	assert.Equal(t, incorrecthints, incorrecthints_results)
}

func TestPodEventer_Namespace_Node_Watcher(t *testing.T) {
	client := k8sfake.NewSimpleClientset()

	log, err := logger.New("service-eventer-test", true)
	assert.NoError(t, err)

	providerDataChan := make(chan providerData, 1)

	comm := MockDynamicComm{
		context.TODO(),
		providerDataChan,
	}

	tests := []struct {
		namespaceEnabled bool
		nodeEnabled      bool
		hintsEnabled     bool
		expectedNil      bool
		name             string
		msg              string
	}{
		{
			namespaceEnabled: false,
			nodeEnabled:      false,
			hintsEnabled:     false,
			expectedNil:      true,
			name:             "add_resource_metadata.namespace and add_resource_metadata.node disabled and hints disabled.",
			msg:              "Watcher should be nil.",
		},
		{
			namespaceEnabled: false,
			nodeEnabled:      false,
			hintsEnabled:     true,
			expectedNil:      false,
			name:             "add_resource_metadata.namespace and add_resource_metadata.node disabled and hints enabled.",
			msg:              "Watcher should not be nil.",
		},
		{
			namespaceEnabled: true,
			nodeEnabled:      true,
			hintsEnabled:     false,
			expectedNil:      false,
			name:             "add_resource_metadata.namespace and add_resource_metadata.node enabled and hints disabled.",
			msg:              "Watcher should not be nil.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var cfg Config
			cfg.InitDefaults()

			nsCfg, err := c.NewConfigFrom(map[string]interface{}{
				"enabled": test.namespaceEnabled,
			})
			assert.NoError(t, err)
			nodeCfg, err := c.NewConfigFrom(map[string]interface{}{
				"enabled": test.nodeEnabled,
			})
			assert.NoError(t, err)

			cfg.AddResourceMetadata.Namespace = nsCfg
			cfg.AddResourceMetadata.Node = nodeCfg
			cfg.Hints.Enabled = test.hintsEnabled

			eventer, err := NewPodEventer(&comm, &cfg, log, client, "cluster", false)
			if err != nil {
				t.Fatal(err)
			}

			namespaceWatcher := eventer.(*pod).namespaceWatcher
			nodeWatcher := eventer.(*pod).nodeWatcher

			if test.expectedNil {
				assert.Equalf(t, nil, namespaceWatcher, "Namespace "+test.msg)
				assert.Equalf(t, nil, nodeWatcher, "Node "+test.msg)
			} else {
				assert.NotEqualf(t, nil, namespaceWatcher, "Namespace "+test.msg)
				assert.NotEqualf(t, nil, nodeWatcher, "Node "+test.msg)
			}
		})
	}
}

// MockDynamicComm is used in tests.
type MockDynamicComm struct {
	context.Context
	providerDataChan chan providerData
}

// AddOrUpdate adds or updates a current mapping.
func (t *MockDynamicComm) AddOrUpdate(id string, priority int, mapping map[string]interface{}, processors []map[string]interface{}) error {
	t.providerDataChan <- providerData{
		id,
		mapping,
		processors,
	}
	return nil
}

// Remove
func (t *MockDynamicComm) Remove(id string) {
}

type podMeta struct{}

// Generate generates pod metadata from a resource object
// All Kubernetes fields that need to be stored under kubernetes. prefix are populated by
// GenerateK8s method while fields that are part of ECS are generated by GenerateECS method
func (p *podMeta) Generate(obj kubernetes.Resource, opts ...metadata.FieldOptions) mapstr.M {
	ecsFields := p.GenerateECS(obj)
	meta := mapstr.M{
		"kubernetes": p.GenerateK8s(obj, opts...),
	}
	meta.DeepUpdate(ecsFields)
	return meta
}

// GenerateECS generates pod ECS metadata from a resource object
func (p *podMeta) GenerateECS(obj kubernetes.Resource) mapstr.M {
	return mapstr.M{
		"orchestrator": mapstr.M{
			"cluster": mapstr.M{
				"name": "devcluster",
				"url":  "8.8.8.8:9090",
			},
		},
	}
}

// GenerateK8s generates pod metadata from a resource object
func (p *podMeta) GenerateK8s(obj kubernetes.Resource, opts ...metadata.FieldOptions) mapstr.M {
	k8sPod, _ := obj.(*kubernetes.Pod)
	return mapstr.M{
		"namespace": k8sPod.GetNamespace(),
		"pod": mapstr.M{
			"uid":  string(k8sPod.GetUID()),
			"name": k8sPod.GetName(),
			"ip":   k8sPod.Status.PodIP,
		},
		"labels": mapstr.M{
			"foo":        "bar",
			"with-dash":  "dash-value",
			"with/slash": "some/path",
		},
		"annotations": mapstr.M{
			"app": "production",
		},
	}
}

// GenerateFromName generates pod metadata from a node name
func (p *podMeta) GenerateFromName(name string, opts ...metadata.FieldOptions) mapstr.M {
	return nil
}
