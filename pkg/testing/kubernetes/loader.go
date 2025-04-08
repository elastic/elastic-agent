// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/yaml"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/e2e-framework/klient/k8s"

	"github.com/elastic/cloud-on-k8s/v2/pkg/apis/agent/v1alpha1"
)

// LoadFromYAML converts the given YAML reader to a list of k8s objects
func LoadFromYAML(reader *bufio.Reader) ([]k8s.Object, error) {
	// if we need to encode/decode more k8s object types in our tests, add them here
	k8sScheme := runtime.NewScheme()
	err := clientsetscheme.AddToScheme(k8sScheme)
	if err != nil {
		return nil, fmt.Errorf("failed to add clientsetscheme: %w", err)
	}
	k8sScheme.AddKnownTypes(schema.GroupVersion{Group: "agent.k8s.elastic.co", Version: "v1alpha1"}, &v1alpha1.Agent{})

	var objects []k8s.Object
	decoder := serializer.NewCodecFactory(k8sScheme).UniversalDeserializer()
	yamlReader := yaml.NewYAMLReader(reader)
	for {
		yamlBytes, err := yamlReader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to read YAML: %w", err)
		}
		obj, _, err := decoder.Decode(yamlBytes, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decode YAML: %w", err)
		}

		k8sObj, ok := obj.(k8s.Object)
		if !ok {
			return nil, fmt.Errorf("failed to cast object to k8s.Object: %v", obj)
		}

		objects = append(objects, k8sObj)
	}

	return objects, nil
}
