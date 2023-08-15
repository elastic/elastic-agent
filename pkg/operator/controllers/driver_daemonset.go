// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package controllers

import (
	"context"
	"fmt"
	"path/filepath"
	"unicode"

	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sClient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/operator/api/v1alpha1"
)

const AgentContainerImageName = "docker.elastic.co/beats/elastic-agent"
const ConfigVolumeName = "config"

func reconcilePodVehicle(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	confgMapName string,
	scheme *runtime.Scheme,
	namespace string,
	serviceAccountName string,
) (bool, error) {
	vehicleName := NamePodVehicle(c.Name)
	reconciliationFunc := reconcileDaemonSet // TODO: make this dynamic and support other kinds
	var toDelete k8sClient.Object
	toDelete = &v1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vehicleName,
			Namespace: namespace,
		},
	}

	if c.Spec.Deployment != nil {
		reconciliationFunc = reconcileDeployment
		toDelete = &v1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      vehicleName,
				Namespace: namespace,
			},
		}
	}

	rn, err := reconciliationFunc(ctx, log, client, c, confgMapName, scheme, namespace, serviceAccountName)
	if err != nil || rn {
		return rn, err
	}

	if err := client.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      vehicleName,
	}, toDelete); err == nil {
		err = client.Delete(ctx, toDelete)
		if err != nil {
			return false, err
		}
	} else if !apierrors.IsNotFound(err) {
		return false, err
	}

	return false, nil
}

func escapeK8sName(base string) string {
	enabledSepcialChard := map[rune]bool{
		'_': true,
		'.': true,
	}

	rr := []rune(base)

	for i, r := range rr {
		if ('a' <= r && r <= 'z') ||
			('0' <= r && r <= '9') {
			continue
		}

		if _, found := enabledSepcialChard[r]; found {
			continue
		}

		if 'A' <= r || r <= 'Z' {
			rr[i] = unicode.ToLower(r)
			continue
		}

		rr[i] = '_'
	}
	return string(rr)
}

func NamePodVehicle(base string) string {
	return escapeK8sName(base + "Vehicle")
}

func NameSecret(base string) string {
	return escapeK8sName(base + "Secret")
}

func NameConfigMap(base string) string {
	return escapeK8sName(base + "Secret")
}

func NamePod(base string) string {
	return escapeK8sName(base + "Pod")
}

func reconcileDaemonSet(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	confgMapName string,
	scheme *runtime.Scheme,
	namespace string,
	servicaAccountName string,
) (bool, error) {
	name := NamePodVehicle(c.Name)

	ds := &v1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"agent.k8s.elastic.co/name": NamePod(c.Name),
				},
			},
			Template: podTemplate(ctx, NamePod(c.Name), c.GroupVersionKind().Version, client, c, confgMapName, servicaAccountName),
			UpdateStrategy: v1.DaemonSetUpdateStrategy{
				Type: v1.OnDeleteDaemonSetStrategyType,
			},
		},
	}
	gvk, err := apiutil.GVKForObject(ds, scheme)
	if err != nil {
		return false, err
	}
	kind := gvk.Kind

	if err := controllerutil.SetControllerReference(c, ds, scheme); err != nil {
		return false, err
	}

	var reconciled v1.DaemonSet
	return false, reconcileResource(ctx, log, compStart, client, ds, &reconciled, name, namespace, kind, true)
}

func reconcileDeployment(ctx context.Context,
	log *logger.Logger,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	confgMapName string,
	scheme *runtime.Scheme,
	namespace string,
	servicaAccountName string,
) (bool, error) {
	name := NamePodVehicle(c.Name)

	ds := &v1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"agent.k8s.elastic.co/name": NamePod(c.Name),
				},
			},
			Template: podTemplate(ctx, NamePod(c.Name), c.GroupVersionKind().Version, client, c, confgMapName, servicaAccountName),
			Replicas: c.Spec.Deployment.Replicas,
		},
	}
	gvk, err := apiutil.GVKForObject(ds, scheme)
	if err != nil {
		return false, err
	}
	kind := gvk.Kind

	if err := controllerutil.SetControllerReference(c, ds, scheme); err != nil {
		return false, err
	}

	var reconciled v1.Deployment
	return false, reconcileResource(ctx, log, compStart, client, ds, &reconciled, name, namespace, kind, true)
}

func podTemplate(ctx context.Context,
	name, version string,
	client k8sClient.Client,
	c *v1alpha1.ElasticAgentComponent,
	secretName string,
	serviceAccountName string,
) corev1.PodTemplateSpec {
	podTemplate := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"agent.k8s.elastic.co/name": name,
			},
		},
	}
	if serviceAccountName != "" {
		podTemplate.Spec.ServiceAccountName = serviceAccountName
	}

	agentContainer := corev1.Container{
		Name:  name,
		Image: fmt.Sprintf("%s:%s", AgentContainerImageName, "8.10.0-SNAPSHOT"), // version),
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      ConfigVolumeName,
				MountPath: filepath.Join(ConfigFilePath, ConfigFileName),
				ReadOnly:  true,
				SubPath:   ConfigFileName,
			},
		},
		Args: []string{
			"-e", "-c", filepath.Join(ConfigFilePath, ConfigFileName),
		},
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"memory": *resource.NewQuantity(600*1024*1024, resource.BinarySI),
			},
			Requests: corev1.ResourceList{
				"cpu":    *resource.NewMilliQuantity(100, resource.DecimalSI),
				"memory": *resource.NewQuantity(300*1024*1024, resource.BinarySI),
			},
		},
	}

	podTemplate.Labels = make(map[string]string)
	podTemplate.Labels["agent.k8s.elastic.co/name"] = name

	// add a config
	notOptional := false
	if podTemplate.Spec.Volumes == nil {
		podTemplate.Spec.Volumes = make([]corev1.Volume, 0, 1)
	}

	podTemplate.Spec.Volumes = append(podTemplate.Spec.Volumes, corev1.Volume{
		Name: ConfigVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: secretName,
				Optional:   &notOptional,
			},
		},
	})

	addVolume(&podTemplate, &agentContainer, "proc", "/hostfs/proc", "/proc", true)
	addVolume(&podTemplate, &agentContainer, "cgroup", "/hostfs/sys/fs/cgroup", "/sys/fs/cgroup", true)
	addVolume(&podTemplate, &agentContainer, "varlibdockercontainers", "/var/lib/docker/containers", "/var/lib/docker/containers", true)
	addVolume(&podTemplate, &agentContainer, "varlog", "/var/log", "/var/log", true)
	addVolume(&podTemplate, &agentContainer, "etc-full", "/hostfs/etc", "/etc", true)        //for Cloud Security Posture integration (cloudbeat)
	addVolume(&podTemplate, &agentContainer, "var-lib", "/hostfs/var/lib", "/var/lib", true) //for Cloud Security Posture integration (cloudbeat)

	if podTemplate.Spec.Containers == nil {
		podTemplate.Spec.Containers = make([]corev1.Container, 0, 1)
	}
	podTemplate.Spec.Containers = append(podTemplate.Spec.Containers, agentContainer)

	return podTemplate
}

func addVolume(t *corev1.PodTemplateSpec, c *corev1.Container, name, mountPath, hostPath string, readonly bool) {
	t.Spec.Volumes = append(t.Spec.Volumes, corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: hostPath,
			},
		},
	})

	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{
		Name:      name,
		MountPath: mountPath,
		ReadOnly:  readonly,
	})
}
