// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package k8s

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/go-elasticsearch/v8"
)

// TestOtelPartialReload benchmarks the OTel partial-reload feature
// (agent.internal.runtime.dynamic_inputs=otel +
// service.partialReload,service.partialReloadReceivers feature gates) against the
// process-runtime baseline.
//
// It deploys a standalone elastic-agent in a kind cluster and continuously scales a
// log-emitter deployment to simulate Kubernetes pod stream churn, which forces a
// stream of config updates. With partial reload working the collector starts once
// and then reconfigures in place; without it, each update costs a full restart.
//
// The only assertion is on delivery: every line each emitter pod wrote must reach
// Elasticsearch (under 1 % loss, no silent pods). Delivery is measured identically
// in both runtimes, so it is the one number that is comparable across arms.
//
// Everything else is logged, not asserted: reload/restart counts from the agent
// logs (otel-only, informational) and per-component plus whole-container CPU and
// memory from agent self-monitoring in Elasticsearch. The resource numbers are the
// benchmark's real output, but they are too machine-dependent to threshold in CI.
func TestOtelPartialReload(t *testing.T) {
	// NOTE: Stack is intentionally omitted. This test deploys a *standalone* agent,
	// so it needs neither Fleet enrollment nor a Kibana client. Building the ES
	// client here instead of via define.Stack also lets the test run against
	// serverless projects, where only API-key auth is available.
	info := define.Require(t, define.Requirements{
		Group: define.Kubernetes,
		OS:    []define.OS{{Type: define.Kubernetes, DockerVariant: "basic"}},
		Local: false,
		Sudo:  false,
	})

	const (
		releaseName   = "partial-reload"
		emitterName   = "log-emitter"
		scaleDuration = 90 * time.Second
		monPeriod     = "10s"
		baseReplicas  = 80
		swingReplicas = 5
		scaleInterval = 5 * time.Second
		// upper bound on how long we poll ES for self-monitoring documents
		monitoringWait = 90 * time.Second
	)

	ctx := context.Background() //nolint:forbidigo // ctx is captured by t.Cleanup in step functions; must outlive the test
	kCtx, esClient := partialReloadContext(t, info)
	testNamespace := kCtx.getNamespace(t)

	// ES_OUTPUT_PRESET selects an Elasticsearch performance preset. This matters for
	// queue sizing: with no preset the translate layer falls back to values that
	// happen to equal the "balanced" preset (queue.mem.events 3200, flush.min_events
	// 1600, flush.timeout 10s, bulk_max_size 1600), but code paths gated on a *named*
	// preset are skipped. Leave unset to exercise the fallback path.
	esOutput := map[string]any{
		"type":    "ESPlainAuthAPI",
		"url":     kCtx.esHost,
		"api_key": kCtx.esAPIKey,
	}
	// DYNAMIC_INPUTS selects the runtime manager for kubernetes-discovered inputs.
	// The point of the benchmark is to compare "otel" against the "process" baseline
	// on delivery and resource cost, so this is the arm selector.
	dynamicInputs := os.Getenv("DYNAMIC_INPUTS")
	if dynamicInputs == "" {
		dynamicInputs = "otel"
	}
	require.Contains(t, []string{"otel", "process"}, dynamicInputs,
		"DYNAMIC_INPUTS must be 'otel' or 'process'")
	t.Logf("dynamic_inputs runtime: %s", dynamicInputs)

	preset := os.Getenv("ES_OUTPUT_PRESET")
	if preset != "" {
		esOutput["preset"] = preset
		t.Logf("elasticsearch output preset: %s", preset)
	} else {
		t.Log("elasticsearch output preset: <none> (translate fallbacks apply)")
	}

	// Pin the exporter's batch flush timer below the publisher's shutdown drain cap.
	//
	// This benchmark measures reload behaviour, and must not be sensitive to data
	// shipping delays. Left at the 10s default, the exporter batcher holds events
	// until it reaches min_size (1600) or its timer fires. Below roughly
	// min_size/drain_cap = 1600/5s ≈ 320 events/sec per receiver, min_size is
	// unreachable in time, so every receiver removal blocks on the batcher until the
	// publisher drain gives up at its 5s cap (receiverPublisherCloseTimeout) — a
	// fixed 5s per removal that has nothing to do with reload, plus re-delivery of
	// the un-acked batch.
	//
	// Pinning the timer under that cap makes drains complete on the timer at any
	// data rate, which removes the confound without depending on the workload
	// producing enough events to fill a batch.
	flushTimeout := "1s"
	if v := os.Getenv("ES_QUEUE_FLUSH_TIMEOUT"); v != "" {
		flushTimeout = v
	}
	if flushTimeout == "default" {
		t.Log("queue.mem.flush.timeout: <translate default> (drain timeouts expected below ~320 ev/s)")
	} else {
		// Nested rather than a dotted key so it renders as real YAML structure.
		esOutput["queue"] = map[string]any{
			"mem": map[string]any{"flush": map[string]any{"timeout": flushTimeout}},
		}
		t.Logf("queue.mem.flush.timeout: %s", flushTimeout)
		if preset != "" && preset != "custom" {
			t.Logf("WARNING: preset %q configures queue.* and will override this flush timeout", preset)
		}
	}

	helmValues := map[string]any{
		// only enable container log collection — no state metrics, no API server etc.
		"kubernetes": map[string]any{
			"enabled":            true,
			"state":              map[string]any{"enabled": false},
			"metrics":            map[string]any{"enabled": false},
			"apiserver":          map[string]any{"enabled": false},
			"proxy":              map[string]any{"enabled": false},
			"scheduler":          map[string]any{"enabled": false},
			"controller_manager": map[string]any{"enabled": false},
			"containers": map[string]any{"logs": map[string]any{
				"enabled": true,
				// Do not block on reading a deleted pod's file to EOF; the scale loop
				// deletes pods continuously and this keeps removals from stalling.
				"vars": map[string]any{"read_until_eof": map[string]any{"enabled": false}},
			}},
			"hints": map[string]any{"enabled": false},
		},
		"kube-state-metrics": map[string]any{"enabled": false},
		"agent": map[string]any{
			"unprivileged": true,
			"image": map[string]any{
				"repository": kCtx.agentImageRepo,
				"tag":        kCtx.agentImageTag,
				"pullPolicy": "Never",
			},
			"presets": map[string]any{
				"perNode": map[string]any{
					"resources": map[string]any{
						"limits":   map[string]any{"memory": "3Gi"},
						"requests": map[string]any{"cpu": "100m", "memory": "400Mi"},
					},
					"agent": map[string]any{
						"monitoring": map[string]any{
							"enabled":        true,
							"metrics":        true,
							"logs":           false,
							"metrics_period": monPeriod,
						},
						"internal": map[string]any{
							"runtime": map[string]any{
								// Which runtime manager handles dynamically-discovered
								// (kubernetes) inputs. "otel" routes them through the
								// collector; "process" runs them as a filebeat subprocess,
								// which is the agent default and the comparison baseline.
								"dynamic_inputs": dynamicInputs,
							},
						},
					},
				},
			},
		},
		"outputs": map[string]any{
			"default": esOutput,
		},
	}

	steps := []k8sTestStep{
		k8sStepCreateNamespace(),
		k8sStepHelmDeploy(AgentHelmChartPath, releaseName, helmValues),
		k8sStepPartialReloadScaleAndAssert(
			esClient, kCtx,
			emitterName, releaseName,
			dynamicInputs,
			scaleDuration, baseReplicas, swingReplicas, scaleInterval,
			monitoringWait,
		),
	}

	for _, step := range steps {
		step(t, ctx, kCtx, testNamespace)
	}
}

// partialReloadContext builds the minimal k8sContext this test needs, plus an
// Elasticsearch client for reading self-monitoring metrics.
//
// It deliberately does not use k8sGetContext: that helper mints a fresh ES API key
// and creates Fleet enrollment params, neither of which a standalone agent test
// needs — and both of which fail on serverless projects where only a pre-existing
// API key is available.
//
// Auth precedence: ELASTICSEARCH_API_KEY (id:secret) is used when set, otherwise
// ELASTICSEARCH_USERNAME/ELASTICSEARCH_PASSWORD.
func partialReloadContext(t *testing.T, info *define.Info) (k8sContext, *elasticsearch.Client) {
	t.Helper()

	agentImage := os.Getenv("AGENT_IMAGE")
	require.NotEmpty(t, agentImage, "AGENT_IMAGE must be set")
	imageParts := strings.SplitN(agentImage, ":", 2)
	require.Len(t, imageParts, 2, "AGENT_IMAGE must be in the form '<repository>:<tag>'")

	client, err := info.KubeClient()
	require.NoError(t, err, "failed to create kube client (is KUBECONFIG set?)")
	clientSet, err := kubernetes.NewForConfig(client.RESTConfig())
	require.NoError(t, err, "failed to create kube clientset")

	// k8sStepHelmDeploy dumps pod logs here when the test fails.
	logsBasePath := os.Getenv("K8S_TESTS_POD_LOGS_BASE")
	if logsBasePath == "" {
		logsBasePath = t.TempDir()
	}
	require.NoError(t, os.MkdirAll(logsBasePath, 0o755)) //nolint:gosec // path comes from the operator running the test

	esHost := os.Getenv("ELASTICSEARCH_HOST")
	require.NotEmpty(t, esHost, "ELASTICSEARCH_HOST must be set")

	esCfg := elasticsearch.Config{Addresses: []string{esHost}}
	// beatsStyleAPIKey is the "id:secret" form the agent's ES output expects.
	var beatsStyleAPIKey string
	rawKey := os.Getenv("ELASTICSEARCH_API_KEY")
	if rawKey != "" {
		require.Contains(t, rawKey, ":", "ELASTICSEARCH_API_KEY must be in 'id:secret' form")
		beatsStyleAPIKey = rawKey
		// the go-elasticsearch client wants the base64 of "id:secret"
		esCfg.APIKey = base64.StdEncoding.EncodeToString([]byte(rawKey))
	} else {
		esUser := os.Getenv("ELASTICSEARCH_USERNAME")
		esPass := os.Getenv("ELASTICSEARCH_PASSWORD")
		require.NotEmpty(t, esUser, "set ELASTICSEARCH_API_KEY or ELASTICSEARCH_USERNAME/PASSWORD")
		require.NotEmpty(t, esPass, "set ELASTICSEARCH_API_KEY or ELASTICSEARCH_USERNAME/PASSWORD")
		esCfg.Username, esCfg.Password = esUser, esPass
	}

	esClient, err := elasticsearch.NewClient(esCfg)
	require.NoError(t, err, "failed to create elasticsearch client")

	if rawKey == "" {
		// The agent's ES output still needs an API key, so mint one with the
		// basic-auth client. info.ESClient cannot be used here: define only builds
		// it when a Stack requirement is declared, which this test omits.
		apiKey, err := generateESAPIKey(esClient, info.Namespace)
		require.NoError(t, err, "failed to generate ES API key")
		decoded, err := base64.StdEncoding.DecodeString(apiKey.Encoded)
		require.NoError(t, err, "failed to decode ES API key")
		beatsStyleAPIKey = string(decoded)
	}

	return k8sContext{
		client:         client,
		clientSet:      clientSet,
		agentImage:     agentImage,
		agentImageRepo: imageParts[0],
		agentImageTag:  imageParts[1],
		logsBasePath:   logsBasePath,
		esHost:         esHost,
		esAPIKey:       beatsStyleAPIKey,
		createdAt:      time.Now(),
	}, esClient
}

// k8sStepPartialReloadScaleAndAssert is a composite step that:
//  1. Deploys the log-emitter workload
//  2. Streams agent pod logs while running the replica scale loop and tracking
//     which emitter pods actually ran
//  3. Logs reload/restart counts parsed from the agent logs (informational)
//  4. Logs per-component and container CPU/memory from self-monitoring in ES
//  5. Asserts that every emitter pod's lines were delivered to ES
func k8sStepPartialReloadScaleAndAssert(
	esClient *elasticsearch.Client,
	kCtx k8sContext,
	emitterDeployment, agentRelease string,
	dynamicInputs string,
	duration time.Duration, baseReplicas, swingReplicas int, scaleInterval time.Duration,
	monitoringWait time.Duration,
) k8sTestStep {
	return func(t *testing.T, ctx context.Context, kCtx k8sContext, namespace string) {
		// 1. Deploy the log-emitter deployment in the default namespace so that the
		//    agent's per-node daemonset (watching the node's containers) discovers it.
		// EMITTER_LINES_PER_SEC tunes per-pod log volume; at the default 100 with
		// baseReplicas=80 that's ~8000 lines/sec, swinging to ~8500 at peak.
		linesPerSec := 100
		if v := os.Getenv("EMITTER_LINES_PER_SEC"); v != "" {
			parsed, err := strconv.Atoi(v)
			require.NoError(t, err, "EMITTER_LINES_PER_SEC must be an integer")
			linesPerSec = parsed
		}
		deployLogEmitter(t, ctx, kCtx, emitterDeployment, namespace, baseReplicas, linesPerSec)

		// 2. Find the agent pod deployed by the daemonset.
		agentPod := waitForAgentPod(t, ctx, kCtx, namespace, agentRelease)
		t.Logf("agent pod: %s", agentPod)

		// Always collect a diagnostics bundle at the end of the run — before helm
		// uninstalls the pod — regardless of pass/fail. The bundle includes goroutine
		// dumps, component config snapshots, and pprof data from the agent process.
		// Set COLLECT_CPU_PROFILE=1 to also capture a 30s CPU profile (adds ~30s to
		// teardown).
		t.Cleanup(func() {
			// ctx is the test-level background context, so it is still live here.
			collectAgentDiagnostics(t, ctx, kCtx, namespace, agentPod, dynamicInputs+"-teardown")
		})

		// Wait for the agent to report healthy, then let it settle. Without this the
		// scale loop would race against startup config churn and we'd be measuring
		// initialization rather than steady-state pod-stream churn.
		var statusOut, statusErr bytes.Buffer
		require.NoErrorf(t,
			k8sCheckAgentStatus(ctx, kCtx.client, &statusOut, &statusErr, namespace, agentPod, "agent", nil),
			"agent never reported healthy\nstdout: %s\nstderr: %s", statusOut.String(), statusErr.String())
		t.Log("agent healthy; letting it settle before scaling")
		time.Sleep(15 * time.Second)

		// 3. Stream agent logs concurrently with the scale loop so we capture every
		//    "component model updated" / "Config updated, restart service" message.
		logCtx, stopLogs := context.WithCancel(ctx)
		var logBuf strings.Builder
		logDone := make(chan struct{})
		go func() {
			defer close(logDone)
			streamPodLogs(logCtx, kCtx, namespace, agentPod, "agent", &logBuf)
		}()

		// 4. Scale loop — drive replica churn for the specified duration.
		//
		// Watch emitter pods throughout so delivery can be checked against the pods
		// that actually existed. Without this, a pod whose logs were never collected
		// at all contributes no documents and is simply absent from the per-pod
		// aggregation, so it cannot be distinguished from a pod that never existed.
		runID := namespace
		watchCtx, stopWatch := context.WithCancel(ctx)
		var podMu sync.Mutex
		type podLife struct{ first, last time.Time }
		createdPods := map[string]*podLife{}
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			for {
				select {
				case <-watchCtx.Done():
					return
				default:
				}
				pods, err := kCtx.clientSet.CoreV1().Pods("default").List(watchCtx, metav1.ListOptions{
					LabelSelector: "app=" + emitterDeployment,
				})
				if err == nil {
					podMu.Lock()
					for _, p := range pods.Items {
						// Only this run's pods. The label selector also matches pods
						// from a previous run still terminating in this namespace;
						// counting those makes them look like they delivered nothing.
						if podRunID(p) != runID {
							continue
						}
						// Only pods we actually saw Running. A pod that is created and
						// deleted again while still in ContainerCreating never executes
						// the emitter, so it legitimately has nothing to deliver and
						// must not be counted as missing data.
						if p.Status.Phase != corev1.PodRunning {
							continue
						}
						now := time.Now()
						if pl, ok := createdPods[p.Name]; ok {
							pl.last = now
						} else {
							createdPods[p.Name] = &podLife{first: now, last: now}
						}
					}
					podMu.Unlock()
				}
				time.Sleep(2 * time.Second)
			}
		}()

		testStart := time.Now()
		runScaleLoop(t, ctx, kCtx, emitterDeployment, duration, baseReplicas, swingReplicas, scaleInterval)

		// Collect a mid-run diagnostics snapshot immediately after the scale loop.
		// This is the most useful moment: if the collector stalled mid-run, its
		// goroutines are most likely still in the stalled state here, before any
		// cleanup or recovery can obscure them. The cleanup-registered snapshot
		// (below) captures teardown state; this one captures the end-of-load state.
		collectAgentDiagnostics(t, ctx, kCtx, namespace, agentPod, dynamicInputs+"-mid-run")

		stopWatch()
		<-watchDone
		podMu.Lock()
		observedPods := make([]string, 0, len(createdPods))
		podLifetimes := map[string]float64{}
		for n, pl := range createdPods {
			observedPods = append(observedPods, n)
			// Lower bound: the pod was Running at least from first to last sighting.
			// The 2s poll means true lifetime is up to ~4s longer.
			podLifetimes[n] = pl.last.Sub(pl.first).Seconds() + 2
		}
		podMu.Unlock()
		sort.Strings(observedPods)

		var lv []float64
		for _, v := range podLifetimes {
			lv = append(lv, v)
		}
		sort.Float64s(lv)
		if len(lv) > 0 {
			t.Logf("emitter pods observed Running: %d — lifetime(s) min=%.0f median=%.0f max=%.0f  all=%v",
				len(observedPods), lv[0], lv[len(lv)/2], lv[len(lv)-1], lv)
		}

		// Stop log streaming.
		stopLogs()
		<-logDone

		rawLogs := logBuf.String()

		// PARTIAL_RELOAD_LOG_DUMP=<path> writes the captured agent logs to a file for
		// offline troubleshooting of reload behaviour.
		if dump := os.Getenv("PARTIAL_RELOAD_LOG_DUMP"); dump != "" {
			if err := os.WriteFile(dump, []byte(rawLogs), 0o644); err != nil { //nolint:gosec // path comes from the operator running the test
				t.Logf("failed to dump logs: %v", err)
			} else {
				t.Logf("dumped %d bytes of agent logs to %s", len(rawLogs), dump)
			}
		}

		// 5. Reload accounting. Informational only: these counts are specific to the
		// otel runtime (process mode does no collector reloads at all), so they are
		// not comparable between arms and are not the benchmark's target.
		updateCount := strings.Count(rawLogs, `"message":"component model updated"`)
		restartCount := strings.Count(rawLogs, `"message":"Config updated, restart service"`)
		partialCount := strings.Count(rawLogs, `"message":"Config updated, performing partial receiver reload"`)
		t.Logf("[informational] component model updates: %d  partial reloads: %d  full restarts: %d",
			updateCount, partialCount, restartCount)

		// 6. The two things we actually care about: was everything delivered, and what
		// did it cost. Both are measured identically in either runtime, so they are
		// directly comparable across arms.
		t.Logf("polling ES up to %s for delivery + resource data…", monitoringWait)
		reportResources(t, ctx, esClient, testStart, monitoringWait)
		stats := verifyDelivery(t, ctx, esClient, testStart, namespace, observedPods, monitoringWait)

		// Loss is the assertion. Duplicates are expected and not a failure: filebeat's
		// registry only advances on ack, so an un-acked batch is re-read from the last
		// persisted offset after a receiver restart. That is at-least-once delivery by
		// design — re-delivery, not data loss.
		if stats.ExpectedSeqs > 0 {
			lossPct := 100 * float64(stats.Lost) / float64(stats.ExpectedSeqs)
			dupPct := 100 * float64(stats.Duplicates) / float64(stats.ExpectedSeqs)
			t.Logf("DELIVERY: pods=%d expected=%d delivered_distinct=%d docs=%d "+
				"lost=%d (%.2f%%) duplicated=%d (%.1f%%)",
				stats.Pods, stats.ExpectedSeqs, stats.DistinctSeqs, stats.DocsDelivered,
				stats.Lost, lossPct, stats.Duplicates, dupPct)
			// 1% tolerance absorbs cardinality approximation and the unread tail of a
			// pod deleted mid-write; real loss shows up far above this.
			if len(stats.PodsSilent) > 0 {
				var detail []string
				for _, n := range stats.PodsSilent {
					detail = append(detail, fmt.Sprintf("%s(~%.0fs alive)", n, podLifetimes[n]))
				}
				t.Errorf("DELIVERY: %d pod(s) ran but delivered nothing: %v",
					len(stats.PodsSilent), detail)
			}
			assert.Lessf(t, lossPct, 1.0,
				"lost %d of %d expected log lines (%.2f%%) in %s mode — gaps in the "+
					"per-pod sequence mean lines were never delivered",
				stats.Lost, stats.ExpectedSeqs, lossPct, dynamicInputs)
		} else {
			t.Error("DELIVERY: no log-emitter documents found in Elasticsearch — " +
				"cannot verify delivery")
		}
	}
}

// podRunID returns the RUN_ID env value of a pod's first container, identifying
// which benchmark run created it.
func podRunID(p corev1.Pod) string {
	if len(p.Spec.Containers) == 0 {
		return ""
	}
	for _, e := range p.Spec.Containers[0].Env {
		if e.Name == "RUN_ID" {
			return e.Value
		}
	}
	return ""
}

// deployLogEmitter creates a busybox deployment in the default namespace that emits
// log lines continuously. The agent's per-node daemonset will discover its container
// and add a pod log stream for each replica — replica changes trigger OTel config
// updates, which is what we measure.
func deployLogEmitter(t *testing.T, ctx context.Context, kCtx k8sContext, name, runID string, initialReplicas, linesPerSec int) {
	t.Helper()
	t.Logf("log-emitter: %d lines/sec/pod x %d pods = %d lines/sec baseline",
		linesPerSec, initialReplicas, linesPerSec*initialReplicas)
	replicas := int32(initialReplicas) //nolint:gosec // replica count is a small test constant
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": name},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:    "logger",
						Image:   "busybox:latest",
						Command: []string{"/bin/sh", "-c"},
						// Emit RATE lines/sec as RATE/10 lines every 100ms. The inner
						// loop uses only shell builtins - calling date(1) per line would
						// fork thousands of processes a second and cap the real rate well
						// below the target.
						Args: []string{
							`if [ "$RATE" -ge 10 ]; then
  BATCH=$(( RATE / 10 )); SLEEP=0.1
else
  BATCH=1; SLEEP=$(awk "BEGIN{printf \"%.2f\", 1/$RATE}")
fi
echo "emitter: RATE=$RATE BATCH=$BATCH SLEEP=$SLEEP" >&2
i=0
while true; do
  n=0
  while [ $n -lt $BATCH ]; do
    echo "[log-emitter] run=$RUN_ID pod=$HOSTNAME seq=$i msg=synthetic load line for partial-reload benchmark padding=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    i=$((i+1)); n=$((n+1))
  done
  sleep $SLEEP
done`,
						},
						Env: []corev1.EnvVar{
							{Name: "RATE", Value: strconv.Itoa(linesPerSec)},
							// Unique per run so delivery accounting cannot pick up
							// documents from an earlier run of this benchmark.
							{Name: "RUN_ID", Value: runID},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    mustParseQuantity("10m"),
								corev1.ResourceMemory: mustParseQuantity("8Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    mustParseQuantity("300m"),
								corev1.ResourceMemory: mustParseQuantity("32Mi"),
							},
						},
					}},
				},
			},
		},
	}

	_, err := kCtx.clientSet.AppsV1().Deployments("default").Create(ctx, deploy, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create log-emitter deployment")

	t.Cleanup(func() {
		_ = kCtx.clientSet.AppsV1().Deployments("default").Delete(
			ctx, name, metav1.DeleteOptions{},
		)
	})

	// Wait for at least one pod to be running before starting the scale loop.
	require.Eventually(t, func() bool {
		d, err := kCtx.clientSet.AppsV1().Deployments("default").Get(ctx, name, metav1.GetOptions{})
		return err == nil && d.Status.ReadyReplicas >= 1
	}, 2*time.Minute, 2*time.Second, "log-emitter deployment never became ready")
}

// waitForAgentPod returns the name of the first agent pod in namespace whose name
// contains the release name. It blocks until one is found.
func waitForAgentPod(t *testing.T, ctx context.Context, kCtx k8sContext, namespace, releaseName string) string {
	t.Helper()
	var podName string
	require.Eventually(t, func() bool {
		pods, err := kCtx.clientSet.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: fmt.Sprintf("name=agent-pernode-%s", releaseName),
		})
		if err != nil || len(pods.Items) == 0 {
			return false
		}
		for _, p := range pods.Items {
			if p.Status.Phase == corev1.PodRunning {
				podName = p.Name
				return true
			}
		}
		return false
	}, 3*time.Minute, 2*time.Second, "agent pod never became Running")
	return podName
}

// streamPodLogs streams log lines from the named container into buf until ctx is
// cancelled. It is intended to run in a goroutine.
func streamPodLogs(ctx context.Context, kCtx k8sContext, namespace, pod, container string, buf *strings.Builder) {
	req := kCtx.clientSet.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{
		Container: container,
		Follow:    true,
	})
	stream, err := req.Stream(ctx)
	if err != nil {
		return
	}
	defer stream.Close()
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		buf.WriteString(scanner.Text())
		buf.WriteByte('\n')
	}
}

// runScaleLoop scales the log-emitter deployment up and down continuously for the
// given duration, triggering OTel config updates on the agent.
func runScaleLoop(
	t *testing.T, ctx context.Context, kCtx k8sContext,
	deployName string, duration time.Duration,
	baseReplicas, swingReplicas int, interval time.Duration,
) {
	t.Helper()
	// SCALE_MODE=up-only never scales down, so no pod is ever deleted. Pod removal
	// races log collection: a pod that lives less than the filestream prospector's
	// scan interval (10s by default) can have its log file deleted before a harvester
	// ever opens it, which looks like delivery loss but is a property of the workload
	// rather than the runtime. up-only isolates that.
	upOnly := os.Getenv("SCALE_MODE") == "up-only"
	maxReplicas := baseReplicas + swingReplicas
	if upOnly {
		maxReplicas = 1 << 30 // never reverse
		t.Log("scale mode: up-only (pods are only added, never deleted)")
	}
	current := baseReplicas
	dir := 1
	deadline := time.Now().Add(duration)

	for time.Now().Before(deadline) {
		next := current + dir
		if next > maxReplicas {
			dir = -1
			next = current + dir
		} else if next < baseReplicas {
			dir = 1
			next = current + dir
		}
		current = next

		patch := fmt.Sprintf(`{"spec":{"replicas":%d}}`, current)
		_, err := kCtx.clientSet.AppsV1().Deployments("default").Patch(
			ctx, deployName, types.MergePatchType, []byte(patch), metav1.PatchOptions{},
		)
		if err != nil {
			t.Logf("scale patch error (will retry): %v", err)
		}
		time.Sleep(interval)
	}
	t.Logf("scale loop done: ran for %s", duration)
}

// reportResources queries agent self-monitoring for per-component CPU and memory
// during the test window and logs a per-component breakdown plus a total.
//
// It deliberately does not filter by component.id: the whole point is to compare
// runtimes, and the components differ between them (otel mode has
// elastic-otel-collector, process mode has a filestream-* beat subprocess). The
// total across all components is the comparable number.
func reportResources(
	t *testing.T, ctx context.Context, esClient *elasticsearch.Client,
	since time.Time, maxWait time.Duration,
) {
	t.Helper()

	// CPU is a cumulative counter, so N samples give N-1 rate intervals.
	const wantSamples = 4

	query := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{"exists": map[string]any{"field": "system.process.cpu.total.value"}},
					map[string]any{"range": map[string]any{
						"@timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)},
					}},
				},
			},
		},
		"size": 2000,
		"sort": []any{map[string]any{"@timestamp": "asc"}},
	}

	var res estools.Documents
	deadline := time.Now().Add(maxWait)
	for {
		var err error
		res, err = estools.PerformQueryForRawQuery(ctx, query, "metrics-elastic_agent*", esClient)
		if err != nil {
			t.Logf("resource ES query failed: %v", err)
			return
		}
		if res.Hits.Total.Value >= wantSamples || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Second)
	}
	if res.Hits.Total.Value == 0 {
		t.Log("resources: no self-monitoring documents found")
		return
	}

	type sample struct {
		ts       time.Time
		cpuMs    float64
		memBytes float64
	}
	type cgCPUSample struct {
		ts time.Time
		ns float64
	}
	byComponent := map[string][]sample{}
	var cgroupMiB []float64
	cgroupCPUByComponent := map[string][]cgCPUSample{}
	for _, hit := range res.Hits.Hits {
		src := hit.Source
		tsRaw, _ := src["@timestamp"].(string)
		ts, tsErr := time.Parse(time.RFC3339Nano, tsRaw)
		cpuMs, cpuOK := extractFloat(src, "system", "process", "cpu", "total", "value")
		if tsErr != nil || !cpuOK {
			continue
		}
		cid, _ := extractString(src, "component", "id")
		if cid == "" {
			cid = "(unknown)"
		}
		s := sample{ts: ts, cpuMs: cpuMs}
		// Per-process memory. NOT cgroup memory: that is reported with id "/" for
		// every component because it is the shared container cgroup, so summing it
		// across components multiplies the same number by the component count.
		if mem, ok := extractFloat(src, "system", "process", "memory", "size"); ok {
			s.memBytes = mem
		}
		// The container totals are tracked separately and reported once.
		if cg, ok := extractFloat(src, "system", "process", "cgroup", "memory", "mem", "usage", "bytes"); ok {
			cgroupMiB = append(cgroupMiB, cg/1024/1024)
		}
		// Cgroup CPU: cumulative nanosecond counter, same value for all processes in
		// the container. Collect per component so we can pick one series for rate math.
		// Try cgroup v2 field first, fall back to v1.
		cgNs, cgNsOK := extractFloat(src, "system", "process", "cgroup", "cpu", "stats", "usage", "ns")
		if !cgNsOK {
			cgNs, cgNsOK = extractFloat(src, "system", "process", "cgroup", "cpuacct", "total", "ns")
		}
		if cgNsOK {
			cgroupCPUByComponent[cid] = append(cgroupCPUByComponent[cid], cgCPUSample{ts: ts, ns: cgNs})
		}
		byComponent[cid] = append(byComponent[cid], s)
	}

	ids := make([]string, 0, len(byComponent))
	for id := range byComponent {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var totalCPU, totalMem float64
	t.Logf("RESOURCES (per component, avg over test window):")
	for _, id := range ids {
		ss := byComponent[id]
		sort.Slice(ss, func(i, j int) bool { return ss[i].ts.Before(ss[j].ts) })
		var milli, mem []float64
		for i := 1; i < len(ss); i++ {
			wallMs := ss[i].ts.Sub(ss[i-1].ts).Seconds() * 1000
			d := ss[i].cpuMs - ss[i-1].cpuMs
			if wallMs <= 0 || d < 0 {
				continue
			}
			milli = append(milli, d/wallMs*1000)
		}
		for _, s := range ss {
			if s.memBytes > 0 {
				mem = append(mem, s.memBytes/1024/1024)
			}
		}
		var cAvg, mAvg float64
		if len(milli) > 0 {
			cAvg, _ = summarize(milli)
		}
		if len(mem) > 0 {
			mAvg, _ = summarize(mem)
		}
		totalCPU += cAvg
		totalMem += mAvg
		t.Logf("  %-28s cpu %6.0fm   mem %6.0f MiB   (n=%d)", id, cAvg, mAvg, len(ss))
	}
	t.Logf("  %-28s cpu %6.0fm   mem %6.0f MiB  (mem = sum of per-process RSS)",
		"TOTAL", totalCPU, totalMem)
	// Container CPU: pick the elastic-agent component's cgroup readings as a
	// single consistent series (all processes share the same cgroup counter).
	// Fall back to any available component if elastic-agent is absent.
	cgCPUSamples := cgroupCPUByComponent["elastic-agent"]
	if len(cgCPUSamples) == 0 {
		for _, v := range cgroupCPUByComponent {
			cgCPUSamples = v
			break
		}
	}
	sort.Slice(cgCPUSamples, func(i, j int) bool { return cgCPUSamples[i].ts.Before(cgCPUSamples[j].ts) })
	var cgCPURates []float64
	for i := 1; i < len(cgCPUSamples); i++ {
		wallNs := float64(cgCPUSamples[i].ts.Sub(cgCPUSamples[i-1].ts).Nanoseconds())
		deltaNs := cgCPUSamples[i].ns - cgCPUSamples[i-1].ns
		if wallNs > 0 && deltaNs >= 0 {
			cgCPURates = append(cgCPURates, deltaNs/wallNs*1000)
		}
	}

	var cgCPULine, cgMemLine string
	if len(cgCPURates) > 0 {
		avg, p95 := summarize(cgCPURates)
		cgCPULine = fmt.Sprintf("cpu %6.0fm (p95 %.0f)", avg, p95)
	} else if len(cgroupMiB) > 0 {
		// The agent's self-monitoring currently ships only cgroup CPU throttling
		// stats, not the usage counter, so container CPU is unavailable; the
		// per-process TOTAL above is the closest substitute.
		cgCPULine = "cpu    n/a (no cgroup usage counter in self-monitoring)"
	}
	if len(cgroupMiB) > 0 {
		avg, p95 := summarize(cgroupMiB)
		cgMemLine = fmt.Sprintf("mem %6.0f MiB (p95 %.0f)", avg, p95)
	}
	if cgCPULine != "" || cgMemLine != "" {
		t.Logf("  %-28s %s  %s — whole-container cgroup, the operator-visible number",
			"CONTAINER", cgCPULine, cgMemLine)
	}
}

// deliveryStats is the per-run delivery accounting used to answer "was all the
// data delivered".
type deliveryStats struct {
	Pods          int
	DocsDelivered int64
	DistinctSeqs  int64
	ExpectedSeqs  int64
	Duplicates    int64
	Lost          int64
	// PodsSilent are pods that existed during the run but delivered no documents.
	PodsSilent []string
}

// verifyDelivery reconstructs delivery from the emitter's per-pod sequence numbers.
//
// Each emitter line carries "pod=<name> seq=<n>" with n increasing from 0 per pod,
// so for any pod the highest sequence observed implies how many lines it produced.
// Comparing that against the distinct sequences actually indexed gives loss, and
// comparing total documents against distinct sequences gives duplication. A runtime
// field extracts seq server-side so this stays an aggregation rather than pulling
// back every document.
func verifyDelivery(
	t *testing.T, ctx context.Context, esClient *elasticsearch.Client,
	since time.Time, runID string, observedPods []string, maxWait time.Duration,
) deliveryStats {
	t.Helper()
	var stats deliveryStats

	const seqScript = `def m = params._source.message;
if (m == null) return;
int i = m.indexOf("seq=");
if (i < 0) return;
int j = m.indexOf(" ", i);
if (j < 0) j = m.length();
try { emit(Long.parseLong(m.substring(i+4, j))); } catch (Exception e) { return; }`

	query := map[string]any{
		"size": 0,
		"runtime_mappings": map[string]any{
			"seq_num": map[string]any{
				"type":   "long",
				"script": map[string]any{"source": seqScript},
			},
		},
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{"match_phrase": map[string]any{
						"message": "synthetic load line for partial-reload benchmark"}},
					// scope strictly to this run
					map[string]any{"match_phrase": map[string]any{
						"message": "run=" + runID}},
					map[string]any{"range": map[string]any{"@timestamp": map[string]any{
						// widen the window: lines emitted before the scale loop and
						// delivered after it still belong to this run
						"gte": since.Add(-5 * time.Minute).UTC().Format(time.RFC3339),
					}}},
				},
			},
		},
		"aggs": map[string]any{
			"pods": map[string]any{
				"terms": map[string]any{"field": "kubernetes.pod.name", "size": 100},
				"aggs": map[string]any{
					"max_seq":  map[string]any{"max": map[string]any{"field": "seq_num"}},
					"distinct": map[string]any{"cardinality": map[string]any{"field": "seq_num", "precision_threshold": 40000}},
				},
			},
		},
	}

	// estools.PerformQueryForRawQuery drops aggregations, so go through the client
	// directly and decode the shape we need.
	runQuery := func() (*deliveryResponse, error) {
		body, err := json.Marshal(query)
		if err != nil {
			return nil, err
		}
		resp, err := esClient.Search(
			esClient.Search.WithContext(ctx),
			esClient.Search.WithIndex("logs-*"),
			esClient.Search.WithBody(bytes.NewReader(body)),
		)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.IsError() {
			return nil, fmt.Errorf("delivery query failed: %s", resp.String())
		}
		var out deliveryResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, err
		}
		return &out, nil
	}

	// Ingestion lags the scale loop; poll until the delivered count stops growing.
	var res *deliveryResponse
	var prevDocs int64 = -1
	deadline := time.Now().Add(maxWait)
	for {
		var err error
		res, err = runQuery()
		if err != nil {
			t.Logf("delivery ES query failed: %v", err)
			return stats
		}
		var docs int64
		for _, b := range res.Aggregations.Pods.Buckets {
			docs += b.DocCount
		}
		if docs > 0 && docs == prevDocs {
			break // count stable => ingestion has settled
		}
		if time.Now().After(deadline) {
			t.Logf("delivery: count still moving at deadline (%d docs), reporting anyway", docs)
			break
		}
		prevDocs = docs
		time.Sleep(10 * time.Second)
	}

	delivered := map[string]struct{}{}
	for _, b := range res.Aggregations.Pods.Buckets {
		if b.MaxSeq.Value == nil || b.Distinct.Value == nil {
			continue
		}
		expected := int64(*b.MaxSeq.Value) + 1
		distinct := int64(*b.Distinct.Value)
		if expected <= 0 || distinct <= 0 {
			continue
		}
		stats.Pods++
		stats.DocsDelivered += b.DocCount
		stats.DistinctSeqs += distinct
		stats.ExpectedSeqs += expected
		if lost := expected - distinct; lost > 0 {
			stats.Lost += lost
		}
		if dup := b.DocCount - distinct; dup > 0 {
			stats.Duplicates += dup
		}
		delivered[b.Key] = struct{}{}
	}

	// Any pod that existed but produced no documents at all is invisible to the
	// per-pod accounting above, so surface it explicitly.
	for _, name := range observedPods {
		if _, ok := delivered[name]; !ok {
			stats.PodsSilent = append(stats.PodsSilent, name)
		}
	}
	return stats
}

// deliveryResponse is the subset of the ES search response verifyDelivery needs.
type deliveryResponse struct {
	Aggregations struct {
		Pods struct {
			Buckets []struct {
				Key      string `json:"key"`
				DocCount int64  `json:"doc_count"`
				MaxSeq   struct {
					Value *float64 `json:"value"`
				} `json:"max_seq"`
				Distinct struct {
					Value *float64 `json:"value"`
				} `json:"distinct"`
			} `json:"buckets"`
		} `json:"pods"`
	} `json:"aggregations"`
}

// extractString navigates a nested map and returns the leaf as a string.
func extractString(m map[string]any, keys ...string) (string, bool) {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = mm[k]
		if !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	return s, ok
}

// extractFloat navigates a nested map[string]any by the given keys and returns the
// final value as float64. Returns false if any key is missing or the type is wrong.
func extractFloat(m map[string]any, keys ...string) (float64, bool) {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur, ok = mm[k]
		if !ok {
			return 0, false
		}
	}
	switch v := cur.(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

// summarize returns the average and p95 of a float64 slice.
func summarize(values []float64) (avg, p95 float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	var sum float64
	for _, v := range sorted {
		sum += v
	}
	avg = sum / float64(len(sorted))
	idx := int(math.Ceil(float64(len(sorted))*0.95)) - 1
	if idx < 0 {
		idx = 0
	}
	p95 = sorted[idx]
	return avg, p95
}

// mustParseQuantity parses a Kubernetes resource quantity and panics on error.
func mustParseQuantity(s string) resource.Quantity {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		panic(fmt.Sprintf("mustParseQuantity(%q): %v", s, err))
	}
	return q
}

// collectAgentDiagnostics runs `elastic-agent diagnostics` inside the agent pod
// and copies the resulting ZIP to kCtx.logsBasePath/<suffix>-diagnostics.zip.
// suffix distinguishes mid-run snapshots ("mid-run") from teardown snapshots
// ("teardown").
//
// The bundle includes goroutine dumps, pprof data, and component config snapshots
// from the agent's control socket. In container mode the agent's monitoring server
// exposes pprof unconditionally, so this always captures meaningful data.
//
// Set COLLECT_CPU_PROFILE=1 to include a 30s CPU profile; that delays teardown
// by roughly that amount.
func collectAgentDiagnostics(t *testing.T, ctx context.Context, kCtx k8sContext, namespace, pod, suffix string) {
	t.Helper()

	remoteZip := "/tmp/ea-diag-" + suffix + ".zip"
	args := []string{"elastic-agent", "diagnostics", "-f", remoteZip}
	if os.Getenv("COLLECT_CPU_PROFILE") != "" {
		args = append(args, "--cpu-profile")
		t.Logf("diagnostics[%s]: collecting CPU profile (~30s)", suffix)
	}

	// Generous timeout: normal ~20s, CPU profile adds 30s more.
	diagCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()

	var diagOut, diagErr bytes.Buffer
	if err := kCtx.client.Resources().ExecInPod(diagCtx, namespace, pod, "agent", args, &diagOut, &diagErr); err != nil {
		t.Logf("diagnostics[%s] exec failed: %v (stderr: %s)", suffix, err, diagErr.String())
		return
	}

	// Exfiltrate the ZIP via base64 — the exec streaming API delivers byte streams
	// faithfully but the k8s client wraps them in JSON frames that can corrupt raw
	// binary if the underlying transport is not careful. Base64 sidesteps this.
	var b64Buf, b64Err bytes.Buffer
	b64Cmd := []string{"sh", "-c", "base64 < " + remoteZip}
	if err := kCtx.client.Resources().ExecInPod(diagCtx, namespace, pod, "agent", b64Cmd, &b64Buf, &b64Err); err != nil {
		t.Logf("diagnostics[%s]: base64 export failed: %v", suffix, err)
		return
	}

	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(b64Buf.String(), "\n", ""))
	if err != nil {
		t.Logf("diagnostics[%s]: base64 decode failed: %v", suffix, err)
		return
	}

	dest := filepath.Join(kCtx.logsBasePath, suffix+"-diagnostics.zip")
	if err := os.WriteFile(dest, raw, 0o644); err != nil { //nolint:gosec // dest is under the operator-provided logs directory
		t.Logf("diagnostics[%s]: write failed: %v", suffix, err)
		return
	}
	t.Logf("agent diagnostics[%s]: %d KiB → %s", suffix, len(raw)/1024, dest)
}
