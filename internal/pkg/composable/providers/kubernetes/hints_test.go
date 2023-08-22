// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package kubernetes

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-autodiscover/kubernetes"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

func TestGenerateHintsMapping(t *testing.T) {
	logger := getLogger()
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
	hints := mapstr.M{
		"hints": mapstr.M{
			"data_streams": "info, key, keyspace",
			"host":         "${kubernetes.pod.ip}:6379",
			"info":         mapstr.M{"period": "1m", "timeout": "41s"},
			"key":          mapstr.M{"period": "10m"},
			"package":      "redis",
			"password":     "password",
			"username":     "username",
			"metrics_path": "/metrics",
			"timeout":      "42s",
			"period":       "42s",
		},
	}

	expected := mapstr.M{
		"redis": mapstr.M{
			"host":         "127.0.0.5:6379",
			"metrics_path": "/metrics",
			"username":     "username",
			"password":     "password",
			"timeout":      "42s",
			"period":       "42s",
			"info": mapstr.M{
				"enabled":      true,
				"host":         "127.0.0.5:6379",
				"period":       "1m",
				"metrics_path": "/metrics",
				"username":     "username",
				"password":     "password",
				"timeout":      "41s",
			}, "key": mapstr.M{
				"enabled":      true,
				"host":         "127.0.0.5:6379",
				"period":       "10m",
				"metrics_path": "/metrics",
				"username":     "username",
				"password":     "password",
				"timeout":      "42s",
			}, "keyspace": mapstr.M{
				"enabled":      true,
				"host":         "127.0.0.5:6379",
				"period":       "42s",
				"metrics_path": "/metrics",
				"username":     "username",
				"password":     "password",
				"timeout":      "42s",
			},
		},
	}

	hintsMapping := GenerateHintsMapping(hints, mapping, logger, "")

	assert.Equal(t, expected, hintsMapping)
}

func TestGenerateHintsMappingWithDefaults(t *testing.T) {
	logger := getLogger()
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
	hints := mapstr.M{
		"hints": mapstr.M{
			"host":         "${kubernetes.pod.ip}:6379",
			"package":      "redis",
			"metrics_path": "/metrics",
			"timeout":      "42s",
			"period":       "42s",
		},
	}

	expected := mapstr.M{
		"redis": mapstr.M{
			"enabled":      true,
			"host":         "127.0.0.5:6379",
			"metrics_path": "/metrics",
			"timeout":      "42s",
			"period":       "42s",
		},
	}

	hintsMapping := GenerateHintsMapping(hints, mapping, logger, "")

	assert.Equal(t, expected, hintsMapping)
}

func TestGenerateHintsMappingWithContainerID(t *testing.T) {
	logger := getLogger()
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
	hints := mapstr.M{
		"hints": mapstr.M{
			"data_streams": "info, key, keyspace",
			"host":         "${kubernetes.pod.ip}:6379",
			"info":         mapstr.M{"period": "1m", "timeout": "41s"},
			"key":          mapstr.M{"period": "10m"},
			"package":      "redis",
			"password":     "password",
			"username":     "username",
			"metrics_path": "/metrics",
			"timeout":      "42s",
			"period":       "42s",
		},
	}

	expected := mapstr.M{
		"container_id": "asdfghjklqwerty",
		"redis": mapstr.M{
			"container_logs": mapstr.M{
				"enabled": true,
			},
			"host":         "127.0.0.5:6379",
			"metrics_path": "/metrics",
			"username":     "username",
			"password":     "password",
			"timeout":      "42s",
			"period":       "42s",
			"info": mapstr.M{
				"enabled":      true,
				"host":         "127.0.0.5:6379",
				"period":       "1m",
				"metrics_path": "/metrics",
				"username":     "username",
				"password":     "password",
				"timeout":      "41s",
			}, "key": mapstr.M{
				"enabled":      true,
				"host":         "127.0.0.5:6379",
				"period":       "10m",
				"metrics_path": "/metrics",
				"username":     "username",
				"password":     "password",
				"timeout":      "42s",
			}, "keyspace": mapstr.M{
				"enabled":      true,
				"host":         "127.0.0.5:6379",
				"period":       "42s",
				"metrics_path": "/metrics",
				"username":     "username",
				"password":     "password",
				"timeout":      "42s",
			},
		},
	}

	hintsMapping := GenerateHintsMapping(hints, mapping, logger, "asdfghjklqwerty")

	assert.Equal(t, expected, hintsMapping)
}

func TestGenerateHintsMappingWithLogStream(t *testing.T) {
	logger := getLogger()
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
	hints := mapstr.M{
		"hints": mapstr.M{
			"data_streams": "access, error",
			"access":       mapstr.M{"stream": "stdout"},
			"error":        mapstr.M{"stream": "stderr"},
			"package":      "apache",
		},
	}

	expected := mapstr.M{
		"container_id": "asdfghjkl",
		"apache": mapstr.M{
			"container_logs": mapstr.M{
				"enabled": true,
			},
			"access": mapstr.M{
				"enabled": true,
				"stream":  "stdout",
			}, "error": mapstr.M{
				"enabled": true,
				"stream":  "stderr",
			},
		},
	}

	hintsMapping := GenerateHintsMapping(hints, mapping, logger, "asdfghjkl")

	assert.Equal(t, expected, hintsMapping)
}

func TestGenerateHintsMappingWithProcessors(t *testing.T) {
	logger := getLogger()
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
				"app":                      "production",
				"co.elastic.hints/package": "apache",
				"co.elastic.hints/processors.1.rename.fields.0.from":   "a.g",
				"co.elastic.hints/processors.1.rename.fields.1.to":     "e.d",
				"co.elastic.hints/processors.1.rename.fail_on_error":   "false",
				"co.elastic.hints/processors.2.add_fields.target":      "project",
				"co.elastic.hints/processors.2.add_fields.fields.name": "myproject",
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
			"co": mapstr.M{
				"elastic": mapstr.M{
					"hints/package": "apache",
					"hints/processors": mapstr.M{
						"rename": mapstr.M{
							"fail_on_error": "false",
							"fields": mapstr.M{
								"from": "a.g",
								"to":   "e.d",
							},
						},
						"add_fields": mapstr.M{
							"target": "project",
							"name":   "myproject",
						},
					},
				},
			},
		},
	}

	expected_hints := mapstr.M{
		"container_id": "asdfghjkl",
		"apache": mapstr.M{
			"container_logs": mapstr.M{
				"enabled": true,
			},
			"enabled": true,
		},
	}

	expected_procesors := []mapstr.M{
		0: {
			"rename": mapstr.M{
				"fail_on_error": "false",
				"fields": mapstr.M{
					"from": "a.g",
					"to":   "e.d",
				},
			},
		},
		1: {
			"add_fields": mapstr.M{
				"target": "project",
				"name":   "myproject",
			},
		},
	}

	hintData := GetHintsMapping(mapping, logger, "co.elastic", "asdfghjkl")

	assert.Equal(t, expected_hints, hintData.composableMapping)
	assert.Equal(t, expected_procesors, hintData.processors)

}
