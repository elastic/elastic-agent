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
				"co.elastic.hints/processors.0.rename.fields.0.from":   "a.g",
				"co.elastic.hints/processors.0.rename.fields.1.to":     "e.d",
				"co.elastic.hints/processors.0.rename.fail_on_error":   "false",
				"co.elastic.hints/processors.1.add_fields.target":      "project",
				"co.elastic.hints/processors.1.add_fields.fields.name": "myproject",
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
			}},
	}

	expectedhints := mapstr.M{
		"container_id": "asdfghjkl",
		"apache": mapstr.M{
			"container_logs": mapstr.M{
				"enabled": true,
			},
			"enabled": true,
		},
	}

	expectedprocesors := []mapstr.M{
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

	assert.Equal(t, expectedhints, hintData.composableMapping)
	//assert.Equal(t, expected_procesors, hintData.processors). We replace this assertion with assert.Contains in order to avoid flakiness in tests because map keys are not sorted
	if len(hintData.processors) > 0 {
		assert.Contains(t, expectedprocesors, hintData.processors[0])
		assert.Contains(t, expectedprocesors, hintData.processors[1])
	}
}

// This test evaluates the hints Generation when you define specific container nginx
// Following will need to include all annotations after top level "co.elastic.hints/" plus those that defined for nginx with prefix "co.elastic.hints.nginx"
// mappings.container.name = nginx defines the container we want to emmit the new configuration. Annotations for other containers like co.elastic.hints.webapp should be excluded
func TestGenerateHintsMappingWithProcessorsForContainer(t *testing.T) {
	logger := getLogger()
	// pod := &kubernetes.Pod{
	// 	ObjectMeta: metav1.ObjectMeta{
	// 		Name:      "testpod",
	// 		UID:       types.UID(uid),
	// 		Namespace: "testns",
	// 		Labels: map[string]string{
	// 			"foo":        "bar",
	// 			"with-dash":  "dash-value",
	// 			"with/slash": "some/path",
	// 		},
	// 		Annotations: map[string]string{
	// 			"app":                      "production",
	// 			"co.elastic.hints/package": "apache",
	// 			"co.elastic.hints/processors.decode_json_fields.fields":         "message",
	// 			"co.elastic.hints/processors.decode_json_fields.add_error_key":  "true",
	// 			"co.elastic.hints/processors.decode_json_fields.overwrite_keys": "true",
	// 			"co.elastic.hints/processors.decode_json_fields.target":         "team",
	// 			"co.elastic.hints.nginx/stream":                                 "stderr",
	// 			"co.elastic.hints.nginx/processors.add_fields.fields.name":      "myproject",
	// 			"co.elastic.hints.webapp/processors.add_fields.fields.name":     "myproject2",
	// 		},
	// 	},
	// 	TypeMeta: metav1.TypeMeta{
	// 		Kind:       "Pod",
	// 		APIVersion: "v1",
	// 	},
	// 	Spec: kubernetes.PodSpec{
	// 		NodeName: "testnode",
	// 	},
	// 	Status: kubernetes.PodStatus{PodIP: "127.0.0.5"},
	// }

	mapping := map[string]interface{}{
		"namespace": "testns",
		"pod": mapstr.M{
			"uid":  string(types.UID(uid)),
			"name": "testpod",
			"ip":   "127.0.0.5",
		},
		"namespace_annotations": mapstr.M{
			"nsa": "nsb",
		},
		"labels": mapstr.M{
			"foo":        "bar",
			"with-dash":  "dash-value",
			"with/slash": "some/path",
		},
		"container": mapstr.M{
			"name": "nginx",
			"id":   "8863418215f5d6b1919db9b3b710615878f88b0773e2b098e714c8d696c3261f",
		},
		"annotations": mapstr.M{
			"app": "production",
			"co": mapstr.M{
				"elastic": mapstr.M{
					"hints/package": "apache",
					"hints/processors": mapstr.M{
						"decode_json_fields": mapstr.M{
							"fields":         "message",
							"add_error_key":  "true",
							"overwrite_keys": "true",
							"target":         "team",
						}},
					"hints": mapstr.M{
						"nginx/processors": mapstr.M{
							"add_fields": mapstr.M{
								"name": "myproject",
							},
						},
						"nginx/stream": "stderr",
					},
				},
			},
		},
	}

	expectedhints := mapstr.M{
		"container_id": "asdfghjkl",
		"apache": mapstr.M{
			"container_logs": mapstr.M{
				"enabled": true,
			},
			"stream":  "stderr",
			"enabled": true,
		},
	}

	expectedprocesors := []mapstr.M{
		0: {
			"decode_json_fields": mapstr.M{
				"fields":         "message",
				"add_error_key":  "true",
				"overwrite_keys": "true",
				"target":         "team",
			},
		},
		1: {
			"add_fields": mapstr.M{
				"name": "myproject",
			},
		},
	}

	hintData := GetHintsMapping(mapping, logger, "co.elastic", "asdfghjkl")

	assert.Equal(t, expectedhints, hintData.composableMapping)
	//assert.Equal(t, expected_procesors, hintData.processors). We replace this assertion with assert.Contains in order to avoid flakiness in tests because map keys are not sorted
	if len(hintData.processors) > 0 {
		assert.Contains(t, expectedprocesors, hintData.processors[0])
		assert.Contains(t, expectedprocesors, hintData.processors[1])
	}
}

func TestDefaultHost(t *testing.T) {
	logger := getLogger()
	cID := "abcd"

	mapping := map[string]interface{}{
		"namespace": "testns",
		"pod": mapstr.M{
			"uid":  string(types.UID(uid)),
			"name": "testpod",
			"ip":   "127.0.0.5",
		},
		"annotations": mapstr.M{
			"app": "production",
			"co": mapstr.M{
				"elastic": mapstr.M{
					"hints/package": "redis",
					"hints": mapstr.M{
						"redis-1/host":   "${kubernetes.pod.ip}:6379",
						"redis-1/stream": "stderr",
						"redis-2/host":   "${kubernetes.pod.ip}:6400",
						"redis-4/stream": "stderr",
					},
				},
			},
		},
	}

	addContainerMapping := func(mapping map[string]interface{}, container mapstr.M) map[string]interface{} {
		clone := make(map[string]interface{}, len(mapping))
		for k, v := range mapping {
			clone[k] = v
		}
		clone["container"] = container
		return clone
	}

	tests := []struct {
		msg      string
		mapping  map[string]interface{}
		expected mapstr.M
	}{
		{
			msg: "Test container with two hints (redis-1), of which one is host.",
			mapping: addContainerMapping(mapping,
				mapstr.M{
					"name": "redis-1",
					"port": "6379",
					"id":   cID,
				},
			),
			expected: mapstr.M{
				"container_id": cID,
				"redis": mapstr.M{
					"container_logs": mapstr.M{
						"enabled": true,
					},
					"enabled": true,
					"host":    "127.0.0.5:6379",
					"stream":  "stderr",
				},
			},
		},
		{
			msg: "Test container with only one hint for host (redis-2).",
			mapping: addContainerMapping(mapping,
				mapstr.M{
					"name": "redis-2",
					"port": "6400",
					"id":   cID,
				},
			),
			expected: mapstr.M{
				"container_id": cID,
				"redis": mapstr.M{
					"container_logs": mapstr.M{
						"enabled": true,
					},
					"enabled": true,
					"host":    "127.0.0.5:6400",
				},
			},
		},
		{
			msg: "Test container without hints and check for the default host (redis-3).",
			mapping: addContainerMapping(mapping,
				mapstr.M{
					"name": "redis-3",
					"port": "7000",
					"id":   cID,
				},
			),
			expected: mapstr.M{
				"container_id": cID,
				"redis": mapstr.M{
					"container_logs": mapstr.M{
						"enabled": true,
					},
					"enabled": true,
					"host":    "127.0.0.5:7000",
				},
			},
		},
		{
			msg: "Test container with one hint for stream and without port defined (redis-4).",
			mapping: addContainerMapping(mapping,
				mapstr.M{
					"name": "redis-4",
					"id":   cID,
				},
			),
			expected: mapstr.M{
				"container_id": cID,
				"redis": mapstr.M{
					"container_logs": mapstr.M{
						"enabled": true,
					},
					"enabled": true,
					"stream":  "stderr",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			hintData := GetHintsMapping(test.mapping, logger, "co.elastic", cID)
			assert.Equal(t, test.expected, hintData.composableMapping)
		})
	}
}
