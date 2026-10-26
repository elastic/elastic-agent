// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"

	otelcomponent "go.opentelemetry.io/collector/component"

	"github.com/elastic/beats/v7/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
)

const (
	FileStorageExtensionType = "file_storage"

	persistentQueueKey        = "queue.persistent"
	persistentQueueConfigPath = persistentQueueKey + ".file_storage"
	PersistentQueueStorageKey = "storage_name"
	persistentQueueDirName    = "exporter-queue"
	kib                       = 1 << 10
	mib                       = 1 << 20
	gib                       = 1 << 30
	persistentQueueMaxRetries = math.MaxInt32
	persistentMinMaxSize      = 2 * mib

	persistentSizingBulkMaxSize          = 100
	persistentSizingLatencyBulkMaxSize   = 50
	persistentSizingLatencyBatchMinBytes = 512 * kib
	persistentSizingQueuePercent         = 95
	persistentSizingBatchMinBytes        = 1 * mib
	persistentSizingBatchMaxBytes        = 90 * mib
	persistentSizingQueueMaxBytes        = 4 * gib
)

func getFileStorageExtensionID(outputName string) otelcomponent.ID {
	return otelcomponent.NewIDWithName(otelcomponent.MustNewType(FileStorageExtensionType), OtelNamePrefix+EncodeNameSegment(outputName))
}

func persistentQueueDir(outputName string) (string, error) {
	base := filepath.Join(paths.Data(), persistentQueueDirName)
	dir := base + string(filepath.Separator) + EncodeNameSegment(outputName)
	if filepath.Clean(dir) != dir || filepath.Dir(dir) != base {
		return "", fmt.Errorf("output name %q is not usable as a queue directory name", outputName)
	}
	return dir, nil
}

// ShareOutputStorage returns a copy of an output made from the output named sourceName, with its persistent
// queue (if any) marked as belonging to sourceName, so the copy shares sourceName's file_storage extension and
// directory. Code that derives an output from a policy output under a new name must use it.
func ShareOutputStorage(output map[string]any, sourceName string) map[string]any {
	queue, _ := output["queue"].(map[string]any)
	persistent, ok := queue["persistent"].(map[string]any)
	if !ok {
		return output
	}
	persistent = maps.Clone(persistent)
	persistent[PersistentQueueStorageKey] = sourceName
	queue = maps.Clone(queue)
	queue["persistent"] = persistent
	output = maps.Clone(output)
	output["queue"] = queue
	return output
}

// RejectReservedOutputKeys returns an error if any output of the policy sets queue.persistent.storage_name,
// which only the agent may set (see ShareOutputStorage).
func RejectReservedOutputKeys(policy map[string]any) error {
	outputs, _ := policy["outputs"].(map[string]any)
	for name, o := range outputs {
		output, _ := o.(map[string]any)
		queue, _ := output["queue"].(map[string]any)
		persistent, _ := queue["persistent"].(map[string]any)
		if _, ok := persistent[PersistentQueueStorageKey]; ok {
			return fmt.Errorf("output %q: %s.%s is set by the agent and must not be configured", name, persistentQueueKey, PersistentQueueStorageKey)
		}
	}
	return nil
}

// extractPersistentQueueConfig removes queue.persistent from output because the beats queue
// namespace allows only one queue type. It returns nil if persistent queue is not configured.
// storageName is the optional queue.persistent.storage_name that lets outputs share one file_storage.
func extractPersistentQueueConfig(output *config.C) (fsCfg *config.C, storageName string, err error) {
	if ok, err := output.Has(persistentQueueConfigPath, -1); err != nil || !ok {
		return nil, "", err
	}
	fsCfg, err = output.Child(persistentQueueConfigPath, -1)
	if err != nil {
		return nil, "", fmt.Errorf("failed reading %s: %w", persistentQueueConfigPath, err)
	}
	storageName, _ = output.String(persistentQueueKey+"."+PersistentQueueStorageKey, -1)
	if _, err := output.Remove(persistentQueueKey, -1); err != nil {
		return nil, "", fmt.Errorf("failed removing %s: %w", persistentQueueKey, err)
	}
	return fsCfg, storageName, nil
}

func validatePersistentMaxSize(fsCfg *config.C) error {
	ok, err := fsCfg.Has("max_size", -1)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s.max_size is required", persistentQueueConfigPath)
	}
	maxSize, err := fsCfg.Int("max_size", -1)
	if err != nil {
		return fmt.Errorf("%s.max_size must be an integer number of bytes: %w", persistentQueueConfigPath, err)
	}
	if maxSize != 0 && maxSize < persistentMinMaxSize {
		return fmt.Errorf("%s.max_size must be 0 (unlimited) or at least %d bytes, got %d", persistentQueueConfigPath, persistentMinMaxSize, maxSize)
	}
	return nil
}

func validatePersistentThresholds(fsCfg *config.C, compaction map[string]any) error {
	if ok, err := fsCfg.Has("max_size", -1); err != nil || !ok {
		return err
	}
	maxSize, err := fsCfg.Int("max_size", -1)
	if err != nil {
		return err
	}
	if maxSize <= 0 {
		return nil
	}
	if onRebound, ok := compaction["on_rebound"].(bool); !ok || !onRebound {
		return nil
	}
	for _, k := range []string{"rebound_needed_threshold_mib", "rebound_trigger_threshold_mib"} {
		path := persistentQueueConfigPath + ".compaction." + k
		if ok, _ := fsCfg.Has("compaction."+k, -1); !ok {
			continue
		}
		v, err := fsCfg.Int("compaction."+k, -1)
		if err != nil {
			return fmt.Errorf("%s must be an integer: %w", path, err)
		}
		if v*mib > maxSize {
			return fmt.Errorf("%s (%d MiB) must not be greater than %s.max_size (%d bytes)", path, v, persistentQueueConfigPath, maxSize)
		}
	}
	return nil
}

func getFileStorageExtensionConfig(fsCfg *config.C, outputName string) (map[string]any, error) {
	extCfg := map[string]any{}
	if err := fsCfg.Unpack(&extCfg); err != nil {
		return nil, fmt.Errorf("failed unpacking %s: %w", persistentQueueConfigPath, err)
	}

	if err := validatePersistentMaxSize(fsCfg); err != nil {
		return nil, err
	}

	dir, err := persistentQueueDir(outputName)
	if err != nil {
		return nil, err
	}
	compactionDir := filepath.Join(dir, "compaction")
	for _, d := range []string{dir, compactionDir} {
		if _, err := os.Stat(d); err == nil {
			continue
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("failed creating persistent queue directory %q: %w", d, err)
		}
		if err := perms.FixPermissions(d, perms.WithMask(0o700)); err != nil {
			return nil, fmt.Errorf("failed restricting persistent queue directory %q: %w", d, err)
		}
	}

	compaction, _ := extCfg["compaction"].(map[string]any)
	compaction = maps.Clone(compaction)
	if compaction == nil {
		compaction = map[string]any{}
	}
	if _, ok := compaction["directory"]; ok {
		return nil, fmt.Errorf("%s.compaction.directory is managed by the agent and must not be set", persistentQueueConfigPath)
	}
	compaction["directory"] = compactionDir
	for _, k := range []string{"on_start", "on_rebound", "cleanup_on_start"} {
		if _, ok := compaction[k]; !ok {
			compaction[k] = true
		}
	}
	if err := validatePersistentThresholds(fsCfg, compaction); err != nil {
		return nil, err
	}
	if maxSize, err := fsCfg.Int("max_size", -1); err == nil && maxSize > 0 {
		if _, ok := compaction["rebound_needed_threshold_mib"]; !ok {
			compaction["rebound_needed_threshold_mib"] = max(maxSize/2/mib, 1)
		}
		if _, ok := compaction["rebound_trigger_threshold_mib"]; !ok {
			compaction["rebound_trigger_threshold_mib"] = max(maxSize/10/mib, 1)
		}
	}

	extCfg["directory"] = dir
	extCfg["create_directory"] = false
	extCfg["recreate"] = true
	extCfg["compaction"] = compaction
	return extCfg, nil
}

// applyPersistentQueue wires a file_storage extension into exporterCfg's sending_queue
// when queue.persistent is configured. It is a no-op otherwise.
func applyPersistentQueue(fsCfg *config.C, preset, outputName string, exporterCfg, extensionCfg map[string]any) error {
	if fsCfg == nil {
		return nil
	}
	fileStorageCfg, err := getFileStorageExtensionConfig(fsCfg, outputName)
	if err != nil {
		return err
	}
	sendingQueue, ok := exporterCfg["sending_queue"].(map[string]any)
	if !ok {
		return fmt.Errorf("exporter has no sending_queue to attach persistent storage to")
	}
	storageID := getFileStorageExtensionID(outputName).String()
	extensionCfg[storageID] = fileStorageCfg
	sendingQueue["storage"] = storageID
	// the exporterhelper rejects wait_for_result together with storage
	delete(sendingQueue, "wait_for_result")
	if retry, ok := exporterCfg["retry"].(map[string]any); ok {
		if _, ok := retry["max_retries"]; ok {
			retry["max_retries"] = persistentQueueMaxRetries
		}
	}
	if usesPersistentSizing(preset) {
		applyPersistentSizing(sendingQueue, fsCfg, preset)
	}
	return nil
}

func usesPersistentSizing(preset string) bool {
	return slices.Contains([]string{"balanced", "throughput", "scale", "latency"}, preset)
}

func applyPersistentSizing(sendingQueue map[string]any, fsCfg *config.C, preset string) {
	minBatch := persistentSizingBatchMinBytes
	if preset == "latency" {
		minBatch = persistentSizingLatencyBatchMinBytes
	}
	queueSize := persistentSizingQueueMaxBytes
	if maxSize, err := fsCfg.Int("max_size", -1); err == nil && maxSize > 0 {
		queueSize = min(queueSize, int(maxSize*persistentSizingQueuePercent/100))
	}
	queueSize = max(queueSize, minBatch)
	maxBatch := min(persistentSizingBatchMaxBytes, queueSize)
	batch, _ := sendingQueue["batch"].(map[string]any)
	if batch == nil {
		batch = map[string]any{}
		sendingQueue["batch"] = batch
	}
	batch["sizer"] = "bytes"
	batch["min_size"] = minBatch
	batch["max_size"] = maxBatch
	sendingQueue["sizer"] = "bytes"
	sendingQueue["queue_size"] = queueSize
	sendingQueue["block_on_overflow"] = true
}
