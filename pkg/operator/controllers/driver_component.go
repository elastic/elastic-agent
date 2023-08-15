// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/operator/api/v1alpha1"
)

const ConfigFileName = "elastic-agent.yml"
const ConfigFilePath = "/usr/share/elastic-agent/"

func reconcileComponent(ctx context.Context,
	log *logger.Logger,
	mode int,
	cfg map[string]interface{},
	comp component.Component,
	client k8sClient.Client,
	owner k8sClient.Object,
	scheme *runtime.Scheme,
	namespace string,
) (bool, error) {
	if mode == compStop {
		return false, onDeleteComponent(ctx, comp, client, owner, namespace)
	}

	// each input is a component
	compCfg, ds, err := filterConfigForComponent(log, cfg, comp)
	if err != nil {
		return false, err
	}

	name := comp.ID
	if strings.HasSuffix(name, "-") {
		name = name + "component"
	}
	expected := &v1alpha1.ElasticAgentComponent{
		ObjectMeta: v1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: v1alpha1.ElasticAgentComponentSpec{
			Policy:       compCfg,
			UpdateNeeded: mode == compUpdate,
		},
	}

	if ds != nil {
		if deplSpec, ok := ds.(v1alpha1.DeploymentSpec); ok {
			expected.Spec.Deployment = &deplSpec
		}
	}

	gvk, err := apiutil.GVKForObject(expected, scheme)
	if err != nil {
		return false, err
	}
	kind := gvk.Kind

	if err := controllerutil.SetControllerReference(owner, expected, scheme); err != nil {
		return false, err
	}

	var reconciled v1alpha1.ElasticAgentComponent
	if rErr := reconcileResource(ctx, log, mode, client, expected, &reconciled, name, namespace, kind, true); rErr != nil {
		err = rErr
	}

	return false, err
}

func onDeleteComponent(ctx context.Context, comp component.Component, client k8sClient.Client, owner k8sClient.Object, namespace string) error {
	toDelete := &v1alpha1.ElasticAgentComponent{}
	if err := client.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      comp.ID,
	}, toDelete); err == nil {
		err = client.Delete(ctx, toDelete)
		if err != nil {
			return err
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

func filterConfigForComponent(log *logger.Logger, cfg map[string]interface{}, comp component.Component) (string, interface{}, error) {
	inputs, ok := cfg["inputs"]
	if !ok {
		return "", nil, fmt.Errorf("config contains no inputs")
	}

	inputsArr, ok := inputs.([]interface{})
	if !ok {
		return "", nil, errors.New("inputs not an array")
	}

	newInputs := make([]interface{}, 0, len(inputsArr))

	var ds interface{}

	for _, inputI := range inputsArr {
		input := inputI.(map[string]interface{})

		inputIdI, ok := input["name"]
		if !ok {
			// TODO: handle
			return "", nil, errors.New("missing id")
		}

		inputID, ok := inputIdI.(string)
		if !ok {
			// TODO: handle
			return "", nil, errors.New("id not a string")
		}

		if !componentContainsID(log, comp, inputID) {
			continue
		}

		if ds == nil {
			dk := getDeploymentKind(log, input)
			if _, ok := dk.(DaemonSetSpec); !ok {
				ds = dk
			}
		}

		newInputs = append(newInputs, inputI)
	}

	// copy map
	newCfg, err := yaml.Marshal(cfg)
	if err != nil {
		return "", nil, err
	}
	var newCfgMap map[string]interface{}
	if err := yaml.Unmarshal(newCfg, &newCfgMap); err != nil {
		return "", nil, err
	}

	newCfgMap["inputs"] = newInputs
	out, err := yaml.Marshal(newCfgMap)
	if err != nil {
		return "", nil, err
	}
	return string(out), ds, nil
}

func getDeploymentKind(log *logger.Logger, inputM map[string]interface{}) interface{} {
	k8sI, ok := inputM["kubernetes"]
	if !ok {
		log.Debugf("Is deployment: No k8s config")
		return DaemonSetSpec{}
	}

	k8sM, ok := k8sI.(map[string]interface{})
	if !ok {
		log.Debugf("Is deployment: k8s config not a map")
		return DaemonSetSpec{}
	}

	if deploymentI, isDeployment := k8sM["deployment"]; isDeployment {
		out, err := yaml.Marshal(deploymentI)
		if err != nil {
			return DaemonSetSpec{}
		}

		ds := v1alpha1.DeploymentSpec{}
		if err := yaml.Unmarshal(out, &ds); err != nil {
			log.Errorf("unmarshal failed %v", ds.Replicas)
		}
		return ds
	}

	return DaemonSetSpec{}
}

func componentContainsID(log *logger.Logger, comp component.Component, name string) bool {
	for _, u := range comp.Units {
		if u.Type == client.UnitTypeOutput {
			// TODO: handle shipper
			continue
		}

		log.Debugf(">> considering unit %s(%s)", u.ID, u.Type.String())
		if u.Config.Name == name {
			log.Debugf(">> found match %s(%s), %s", u.ID, u.Type.String(), name)
			return true
		}
	}
	return false
}

type DaemonSetSpec struct{}
