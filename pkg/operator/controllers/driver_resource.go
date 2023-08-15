// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package controllers

import (
	"context"
	"fmt"
	"reflect"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
)

func reconcileResource(ctx context.Context,
	log *logger.Logger,
	mode int,
	client k8sClient.Client,
	expected k8sClient.Object,
	reconciled k8sClient.Object,
	name, namespace, kind string,
	needsRecreate bool,
) error {
	return reconcileResourceForce(ctx,
		log,
		mode,
		client,
		expected, reconciled,
		name, namespace, kind,
		needsRecreate,
		false)
}

func reconcileResourceForce(ctx context.Context,
	log *logger.Logger,
	mode int,
	client k8sClient.Client,
	expected k8sClient.Object,
	reconciled k8sClient.Object,
	name, namespace, kind string,
	needsRecreate bool,
	force bool,
) error {
	create := func() error {
		expectedCopyValue := reflect.ValueOf(expected.DeepCopyObject()).Elem()
		reflect.ValueOf(reconciled).Elem().Set(expectedCopyValue)
		// Create the object, which modifies params.Reconciled in-place
		err := client.Create(ctx, reconciled)
		if err != nil {
			filteredErr := k8sClient.IgnoreAlreadyExists(err)
			if filteredErr == nil && needsRecreate {
				client.Update(ctx, reconciled)
			}
			return filteredErr
		}
		return nil
	}

	// Check if already exists
	err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, reconciled)
	if err != nil && apierrors.IsNotFound(err) {
		log.Debugf("component not found, will create %s", expected.GetName())
		return create()
	} else if err != nil {
		log.Errorf("get component errored, %s", expected.GetName())
		return fmt.Errorf("failed to get %s %s/%s: %w", kind, namespace, name, err)
	}

	log.Debugf("component %s found, needs recreate %v", expected.GetName(), needsRecreate)
	if force {
		reconciledMeta, err := meta.Accessor(reconciled)
		if err != nil {
			return err
		}

		uidToDelete := reconciledMeta.GetUID()
		resourceVersionToDelete := reconciledMeta.GetResourceVersion()
		opt := k8sClient.Preconditions{
			UID:             &uidToDelete,
			ResourceVersion: &resourceVersionToDelete,
		}

		err = client.Delete(ctx, expected, opt)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete %s %s/%s: %w", kind, namespace, name, err)
		}
		return create()
	}
	if needsRecreate {
		if reflect.DeepEqual(expected, reconciled) {
			log.Debugf("equal components, skipping update")
			return nil
		}

		// copy resource version to expected so update match obejcts
		reconciledMeta, err := meta.Accessor(reconciled)
		if err != nil {
			return err
		}
		resourceVersion := reconciledMeta.GetResourceVersion()

		expectedMeta, err := meta.Accessor(expected)
		if err != nil {
			return err
		}
		expectedMeta.SetResourceVersion(resourceVersion)
		log.Debugf("component  %s being updated", expected.GetName())

		err = client.Update(ctx, expected)
		if err != nil {
			log.Errorf("component  %s being updated with error %v", expected.GetName(), err)
			return err
		}
		log.Debugf("component  %s updated", expected.GetName())
	}

	return nil
}
