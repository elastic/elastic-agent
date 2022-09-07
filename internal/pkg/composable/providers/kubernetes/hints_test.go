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
			"data_streams": "info, key",
			"host":         "${kubernetes.pod.ip}:6379",
			"info":         mapstr.M{"period": "1m"},
			"key":          mapstr.M{"period": "10m"},
			"package":      "redis",
		},
	}
	expected := mapstr.M{
		"redis": mapstr.M{
			"enabled": true,
			"host":    "127.0.0.5:6379",
			"info": mapstr.M{
				"enabled": true,
				"host":    "127.0.0.5:6379",
				"period":  "1m",
			}, "key": mapstr.M{
				"enabled": true,
				"host":    "127.0.0.5:6379",
				"period":  "10m",
			},
		},
	}

	hintsMapping := GenerateHintsMapping(hints, mapping, logger, "")

	assert.Equal(t, expected, hintsMapping)
}
