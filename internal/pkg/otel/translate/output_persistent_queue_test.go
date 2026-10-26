// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/pkg/config"
	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func TestESToOTelConfigPersistentQueue(t *testing.T) {
	top := t.TempDir()
	prev := paths.Top()
	paths.SetTop(top)
	t.Cleanup(func() { paths.SetTop(prev) })

	base := `
hosts: ["localhost:9200"]
username: elastic
password: changeme
`
	t.Run("enabled", func(t *testing.T) {
		cfg := config.MustNewConfigFrom(base + `
queue:
  persistent:
    file_storage:
      timeout: 1s
      max_size: 262144000
      fsync: true
`)
		got, _, ext, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
		require.NoError(t, err)

		id := getFileStorageExtensionID("default").String()
		sq := got["sending_queue"].(map[string]any)
		require.Equal(t, id, sq["storage"])
		require.NotContains(t, sq, "wait_for_result")
		require.EqualValues(t, 2147483647, got["retry"].(map[string]any)["max_retries"])

		dir := filepath.Join(paths.Data(), "exporter-queue", "default")
		fs := ext[id].(map[string]any)
		require.Equal(t, dir, fs["directory"])
		require.Equal(t, false, fs["create_directory"])
		require.Equal(t, true, fs["recreate"])
		require.Equal(t, true, fs["fsync"])
		comp := fs["compaction"].(map[string]any)
		require.Equal(t, filepath.Join(dir, "compaction"), comp["directory"])
		require.EqualValues(t, 125, comp["rebound_needed_threshold_mib"])
		require.EqualValues(t, 25, comp["rebound_trigger_threshold_mib"])

		info, err := os.Stat(dir)
		require.NoError(t, err)
		if runtime.GOOS != "windows" {
			require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
		}
	})

	t.Run("user_compaction_directory_rejected", func(t *testing.T) {
		cfg := config.MustNewConfigFrom(base + `
queue:
  persistent:
    file_storage:
      max_size: 262144000
      compaction:
        directory: /custom
        on_start: false
        rebound_needed_threshold_mib: 7
`)
		_, _, _, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
		require.ErrorContains(t, err, "compaction.directory is managed by the agent")
	})

	t.Run("user_compaction_kept", func(t *testing.T) {
		cfg := config.MustNewConfigFrom(base + `
queue:
  persistent:
    file_storage:
      max_size: 262144000
      compaction:
        on_start: false
        rebound_needed_threshold_mib: 7
`)
		_, _, ext, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
		require.NoError(t, err)
		comp := ext[getFileStorageExtensionID("default").String()].(map[string]any)["compaction"].(map[string]any)
		require.Equal(t, false, comp["on_start"])
		require.EqualValues(t, 7, comp["rebound_needed_threshold_mib"])
		require.Equal(t, true, comp["on_rebound"])
		require.EqualValues(t, 25, comp["rebound_trigger_threshold_mib"])
	})

	for name, size := range map[string]string{"too_small": "1000", "below_minimum": "2097151", "string": "250MB"} {
		t.Run("invalid_max_size_"+name, func(t *testing.T) {
			cfg := config.MustNewConfigFrom(base + `
preset: balanced
queue:
  persistent:
    file_storage:
      max_size: ` + size + `
`)
			_, _, _, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
			require.ErrorContains(t, err, "max_size")
		})
	}

	t.Run("minimum_max_size_accepted", func(t *testing.T) {
		cfg := config.MustNewConfigFrom(base + `
preset: balanced
queue:
  persistent:
    file_storage:
      max_size: 2097152
`)
		_, _, _, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
		require.NoError(t, err)
	})

	for _, preset := range []string{"balanced", "throughput", "scale", "latency", "custom"} {
		t.Run("preset_"+preset, func(t *testing.T) {
			cfg := config.MustNewConfigFrom(base + "preset: " + preset + `
queue:
  persistent:
    file_storage:
      max_size: 262144000
`)
			got, _, ext, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
			require.NoError(t, err)

			id := getFileStorageExtensionID("default").String()
			sq := got["sending_queue"].(map[string]any)
			require.Equal(t, id, sq["storage"])
			require.NotContains(t, sq, "wait_for_result")
			require.Contains(t, ext, id)
		})
	}

	t.Run("disabled", func(t *testing.T) {
		got, _, ext, err := ESToOTelConfig(config.MustNewConfigFrom(base), "default", logp.NewNopLogger())
		require.NoError(t, err)
		sq := got["sending_queue"].(map[string]any)
		require.NotContains(t, sq, "storage")
		require.Equal(t, true, sq["wait_for_result"])
		require.NotContains(t, ext, getFileStorageExtensionID("default").String())
	})
}

func bytesQueue(flush string, consumers int) map[string]any {
	return bytesQueueWithMin(flush, consumers, 1*mib)
}

func bytesQueueWithMin(flush string, consumers, minSize int) map[string]any {
	return map[string]any{
		"batch": map[string]any{
			"flush_timeout": flush,
			"max_size":      90 * mib,
			"min_size":      minSize,
			"sizer":         "bytes",
		},
		"block_on_overflow": true,
		"enabled":           true,
		"num_consumers":     consumers,
		"queue_size":        262144000 * 95 / 100,
		"sizer":             "bytes",
	}
}

func TestESToOTelConfigPersistentQueueFullConfig(t *testing.T) {
	tests := []struct {
		preset          string
		maxConns        int
		idleConnTimeout string
		initialBackoff  time.Duration
		maxBackoff      time.Duration
		sendingQueue    map[string]any
	}{
		{"", 1, "3s", 1 * time.Second, 60 * time.Second, bytesQueue("10s", 2)},
		{"custom", 1, "3s", 1 * time.Second, 60 * time.Second, bytesQueue("10s", 2)},
		{"balanced", 1, "3s", 1 * time.Second, 60 * time.Second, bytesQueue("10s", 2)},
		{"throughput", 4, "15s", 1 * time.Second, 60 * time.Second, bytesQueue("5s", 5)},
		{"scale", 1, "1s", 5 * time.Second, 300 * time.Second, bytesQueue("20s", 2)},
		{"latency", 1, "1m0s", 1 * time.Second, 60 * time.Second, bytesQueueWithMin("1s", 2, 512*kib)},
	}

	for _, tc := range tests {
		t.Run("preset_"+tc.preset, func(t *testing.T) {
			top := t.TempDir()
			prev := paths.Top()
			paths.SetTop(top)
			t.Cleanup(func() { paths.SetTop(prev) })

			cfgYAML := `
hosts: ["localhost:9200"]
username: elastic
password: changeme
queue:
  persistent:
    file_storage:
      timeout: 1s
      max_size: 262144000
      fsync: true
`
			if tc.preset != "" {
				cfgYAML += "preset: " + tc.preset + "\n"
			}
			got, _, ext, err := ESToOTelConfig(config.MustNewConfigFrom(cfgYAML), "default", logp.NewNopLogger())
			require.NoError(t, err)

			dir := filepath.Join(paths.Data(), "exporter-queue", "default")
			authID := "beatsauth/_agent-component/default"
			storageID := "file_storage/_agent-component/default"

			wantSendingQueue := maps.Clone(tc.sendingQueue)
			wantSendingQueue["storage"] = storageID

			wantExporter := map[string]any{
				"auth":                      map[string]any{"authenticator": authID},
				"bulk_response_filter_path": "errors,items.*.error,items.*.status,items.*.failure_store",
				"compression":               "gzip",
				"compression_params":        map[string]any{"level": 1},
				"endpoints":                 []string{"http://localhost:9200"},
				"include_source_on_error":   true,
				"logs_dynamic_id":           map[string]any{"enabled": true},
				"logs_dynamic_pipeline":     map[string]any{"enabled": true},
				"max_conns_per_host":        tc.maxConns,
				"password":                  "changeme",
				"retry": map[string]any{
					"enabled":                  true,
					"initial_interval":         tc.initialBackoff,
					"max_interval":             tc.maxBackoff,
					"max_retries":              2147483647,
					"retry_on_document_status": []int{429, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511},
					"retry_on_status": []int{
						300, 301, 302, 303, 304, 305, 307, 308,
						400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 414, 415, 416, 417, 418,
						421, 422, 423, 424, 425, 426, 428, 429, 431, 451,
						500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511,
					},
				},
				"sending_queue":            wantSendingQueue,
				"suppress_conflict_errors": true,
				"timeout":                  90 * time.Second,
				"user":                     "elastic",
				"version_detection":        map[string]any{"enabled": false},
			}
			require.Equal(t, wantExporter, got)

			wantExtensions := map[string]any{
				authID: map[string]any{
					"auth":                    map[string]any{"password": "changeme", "username": "elastic"},
					"continue_on_error":       true,
					"endpoints":               []string{"http://localhost:9200"},
					"idle_connection_timeout": tc.idleConnTimeout,
					"proxy_disable":           false,
					"timeout":                 "1m30s",
				},
				storageID: map[string]any{
					"compaction": map[string]any{
						"cleanup_on_start":              true,
						"directory":                     filepath.Join(dir, "compaction"),
						"on_rebound":                    true,
						"on_start":                      true,
						"rebound_needed_threshold_mib":  int64(125),
						"rebound_trigger_threshold_mib": int64(25),
					},
					"create_directory": false,
					"directory":        dir,
					"fsync":            true,
					"max_size":         uint64(262144000),
					"recreate":         true,
					"timeout":          "1s",
				},
			}
			require.Equal(t, wantExtensions, ext)
		})
	}
}

func TestESToOTelConfigBalancedPersistentQueueBatchMax(t *testing.T) {
	prev := paths.Top()
	paths.SetTop(t.TempDir())
	t.Cleanup(func() { paths.SetTop(prev) })

	build := func(fileStorage string) map[string]any {
		cfg := config.MustNewConfigFrom(`
hosts: ["localhost:9200"]
username: elastic
password: changeme
preset: balanced
queue:
  persistent:
    file_storage:
` + fileStorage)
		got, _, _, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
		require.NoError(t, err)
		return got["sending_queue"].(map[string]any)
	}

	for _, tc := range []struct {
		fileStorage string
		wantBatch   int
		wantQueue   int
	}{
		{"      max_size: 52428800\n", 52428800 * 95 / 100, 52428800 * 95 / 100},
		{"      max_size: 157286400\n", 90 * mib, 157286400 * 95 / 100},
		{"      max_size: 1073741824\n", 90 * mib, 1073741824 * 95 / 100},
		{"      max_size: 4294967296\n", 90 * mib, 4294967296 * 95 / 100},
		{"      max_size: 8589934592\n", 90 * mib, 4 * gib},
		{"      max_size: 0\n", 90 * mib, 4 * gib},
	} {
		sq := build(tc.fileStorage)
		require.Equal(t, tc.wantBatch, sq["batch"].(map[string]any)["max_size"])
		require.Equal(t, tc.wantQueue, sq["queue_size"])
		require.Equal(t, "bytes", sq["sizer"])
	}
}

func TestESToOTelConfigPersistentQueueNoPresetUserOverrides(t *testing.T) {
	prev := paths.Top()
	paths.SetTop(t.TempDir())
	t.Cleanup(func() { paths.SetTop(prev) })

	for _, preset := range []string{"", "preset: custom\n"} {
		cfg := config.MustNewConfigFrom(`
hosts: ["localhost:9200"]
username: elastic
password: changeme
worker: 3
bulk_max_size: 500
idle_connection_timeout: 7s
queue:
  mem:
    events: 9000
  persistent:
    file_storage:
      max_size: 262144000
` + preset)
		got, _, ext, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
		require.NoError(t, err)

		sq := got["sending_queue"].(map[string]any)
		require.Equal(t, 4, sq["num_consumers"])
		require.Equal(t, "bytes", sq["sizer"])
		require.Equal(t, 262144000*95/100, sq["queue_size"])

		auth := ext["beatsauth/_agent-component/default"].(map[string]any)
		require.Equal(t, "7s", auth["idle_connection_timeout"])

		queue, err := cfg.Child("queue", -1)
		require.NoError(t, err)
		events, err := queue.Int("mem.events", -1)
		require.NoError(t, err)
		require.EqualValues(t, 9000, events)
		minEvents, err := queue.Int("mem.flush.min_events", -1)
		require.NoError(t, err)
		require.EqualValues(t, 100, minEvents)
	}
}

func TestESToOTelConfigBalancedWithoutPersistentQueueUnchanged(t *testing.T) {
	cfg := config.MustNewConfigFrom(`
hosts: ["localhost:9200"]
username: elastic
password: changeme
preset: balanced
`)
	got, _, ext, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
	require.NoError(t, err)

	sq := got["sending_queue"].(map[string]any)
	require.Equal(t, 6400, sq["queue_size"])
	require.Equal(t, "items", sq["batch"].(map[string]any)["sizer"])
	require.NotContains(t, sq, "sizer")
	require.NotContains(t, sq, "storage")
	require.NotContains(t, ext, getFileStorageExtensionID("default").String())
}

func TestESToOTelConfigPersistentQueueBeatsQueue(t *testing.T) {
	prev := paths.Top()
	paths.SetTop(t.TempDir())
	t.Cleanup(func() { paths.SetTop(prev) })

	tests := []struct {
		preset                          string
		events, minEvents               int
		persistentEvents, persistentMin int
		timeout                         string
	}{
		{"balanced", 6400, 1600, 400, 100, "10s"},
		{"throughput", 16000, 1600, 1000, 100, "5s"},
		{"scale", 6400, 1600, 400, 100, "20s"},
		{"latency", 4100, 2050, 200, 50, "1s"},
	}
	for _, tc := range tests {
		for _, persistent := range []bool{false, true} {
			yaml := `
hosts: ["localhost:9200"]
username: elastic
password: changeme
preset: ` + tc.preset + "\n"
			wantEvents, wantMinEvents := tc.events, tc.minEvents
			if persistent {
				yaml += `
queue:
  persistent:
    file_storage:
      max_size: 262144000
`
				wantEvents, wantMinEvents = tc.persistentEvents, tc.persistentMin
			}
			cfg := config.MustNewConfigFrom(yaml)
			_, _, _, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
			require.NoError(t, err)

			q, err := cfg.Child("queue", -1)
			require.NoError(t, err)
			events, err := q.Int("mem.events", -1)
			require.NoError(t, err)
			minEvents, err := q.Int("mem.flush.min_events", -1)
			require.NoError(t, err)
			timeout, err := q.String("mem.flush.timeout", -1)
			require.NoError(t, err)
			msg := fmt.Sprintf("preset=%s persistent=%v", tc.preset, persistent)
			require.EqualValues(t, wantEvents, events, msg)
			require.EqualValues(t, wantMinEvents, minEvents, msg)
			require.Equal(t, tc.timeout, timeout, msg)
		}
	}
}

func TestESToOTelConfigPersistentQueueSharedStorage(t *testing.T) {
	top := t.TempDir()
	prev := paths.Top()
	paths.SetTop(top)
	t.Cleanup(func() { paths.SetTop(prev) })

	const base = `
hosts: ["localhost:9200"]
username: elastic
password: changeme
queue:
  persistent:
    file_storage:
      max_size: 10485760
`
	translateAs := func(t *testing.T, name, extra string) (map[string]any, map[string]any) {
		t.Helper()
		cfg := config.MustNewConfigFrom(base + extra)
		got, _, ext, err := ESToOTelConfig(cfg, name, logp.NewNopLogger())
		require.NoError(t, err)
		return got, ext
	}

	t.Run("same_use_output_shares_storage", func(t *testing.T) {
		gotDefault, extDefault := translateAs(t, "default", "")
		gotMon, extMon := translateAs(t, "monitoring", "    storage_name: default\n")

		id := getFileStorageExtensionID("default").String()
		require.Equal(t, id, gotDefault["sending_queue"].(map[string]any)["storage"])
		require.Equal(t, id, gotMon["sending_queue"].(map[string]any)["storage"])
		require.Equal(t, extDefault[id], extMon[id])
		require.NotContains(t, extMon, getFileStorageExtensionID("monitoring").String())
		require.NoDirExists(t, filepath.Join(paths.Data(), "exporter-queue", "monitoring"))
	})

	t.Run("different_use_output_unique_storage", func(t *testing.T) {
		gotDefault, extDefault := translateAs(t, "default", "")
		gotMon, extMon := translateAs(t, "monitoring", "    storage_name: other\n")

		defaultID := getFileStorageExtensionID("default").String()
		otherID := getFileStorageExtensionID("other").String()
		require.Equal(t, defaultID, gotDefault["sending_queue"].(map[string]any)["storage"])
		require.Equal(t, otherID, gotMon["sending_queue"].(map[string]any)["storage"])
		require.NotEqual(t, extDefault[defaultID].(map[string]any)["directory"], extMon[otherID].(map[string]any)["directory"])
	})

	t.Run("storage_name_honored_for_any_output_name", func(t *testing.T) {
		got, ext := translateAs(t, "anything", "    storage_name: default\n")
		id := getFileStorageExtensionID("default").String()
		require.Equal(t, id, got["sending_queue"].(map[string]any)["storage"])
		require.Contains(t, ext, id)
	})

	t.Run("storage_name_not_passed_to_extension", func(t *testing.T) {
		_, ext := translateAs(t, "monitoring", "    storage_name: default\n")
		require.NotContains(t, ext[getFileStorageExtensionID("default").String()], "storage_name")
	})
}

func TestPersistentQueueDirRejectsUnsafeNames(t *testing.T) {
	top := t.TempDir()
	prev := paths.Top()
	paths.SetTop(top)
	t.Cleanup(func() { paths.SetTop(prev) })

	for _, name := range []string{"", ".", "..", "../x", "a/b", "a/../b", "a//b", "/abs"} {
		_, err := persistentQueueDir(name)
		require.Error(t, err, name)
	}
	for _, name := range []string{"default", "my output", "a%2Fb", "x.y", "..."} {
		dir, err := persistentQueueDir(name)
		require.NoError(t, err, name)
		require.Equal(t, filepath.Join(paths.Data(), "exporter-queue"), filepath.Dir(dir))
	}
}

func TestRejectReservedOutputKeys(t *testing.T) {
	policy := func(persistent map[string]any) map[string]any {
		return map[string]any{"outputs": map[string]any{
			"default": map[string]any{"queue": map[string]any{"persistent": persistent}},
		}}
	}
	require.NoError(t, RejectReservedOutputKeys(policy(map[string]any{"file_storage": map[string]any{}})))
	require.NoError(t, RejectReservedOutputKeys(map[string]any{}))
	require.ErrorContains(t, RejectReservedOutputKeys(policy(map[string]any{PersistentQueueStorageKey: "x"})), PersistentQueueStorageKey)
}

func TestShareOutputStorage(t *testing.T) {
	src := map[string]any{"queue": map[string]any{"persistent": map[string]any{"file_storage": map[string]any{}}}}
	got := ShareOutputStorage(src, "default")
	require.Equal(t, "default", got["queue"].(map[string]any)["persistent"].(map[string]any)[PersistentQueueStorageKey])
	require.NotContains(t, src["queue"].(map[string]any)["persistent"], PersistentQueueStorageKey)

	plain := map[string]any{"type": "elasticsearch"}
	require.Equal(t, plain, ShareOutputStorage(plain, "default"))
}

func TestPersistentQueueUserThresholds(t *testing.T) {
	top := t.TempDir()
	prev := paths.Top()
	paths.SetTop(top)
	t.Cleanup(func() { paths.SetTop(prev) })

	translateWith := func(compaction string) error {
		cfg := config.MustNewConfigFrom(`
hosts: ["localhost:9200"]
username: elastic
password: changeme
preset: balanced
queue:
  persistent:
    file_storage:
      max_size: 10485760
      compaction:
` + compaction)
		_, _, _, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
		return err
	}

	require.ErrorContains(t, translateWith("        rebound_needed_threshold_mib: 11\n"), "rebound_needed_threshold_mib")
	require.ErrorContains(t, translateWith("        rebound_trigger_threshold_mib: 11\n"), "rebound_trigger_threshold_mib")
	require.NoError(t, translateWith("        rebound_needed_threshold_mib: 10\n"))
	require.NoError(t, translateWith("        on_rebound: false\n        rebound_needed_threshold_mib: 11\n"))
}

func TestPersistentQueueFileStorageOptions(t *testing.T) {
	prev := paths.Top()
	paths.SetTop(t.TempDir())
	t.Cleanup(func() { paths.SetTop(prev) })

	translateWith := func(fileStorage string) (map[string]any, error) {
		cfg := config.MustNewConfigFrom(`
hosts: ["localhost:9200"]
username: elastic
password: changeme
queue:
  persistent:
    file_storage:
` + fileStorage)
		_, _, ext, err := ESToOTelConfig(cfg, "default", logp.NewNopLogger())
		if err != nil {
			return nil, err
		}
		return ext[getFileStorageExtensionID("default").String()].(map[string]any), nil
	}

	t.Run("max_size_required", func(t *testing.T) {
		for _, fs := range []string{"      fsync: true\n", "      {}\n"} {
			_, err := translateWith(fs)
			require.ErrorContains(t, err, "max_size is required")
		}
	})

	t.Run("only_max_size_gives_agent_defaults", func(t *testing.T) {
		fs, err := translateWith("      max_size: 262144000\n")
		require.NoError(t, err)
		comp := fs["compaction"].(map[string]any)
		require.Equal(t, true, comp["on_start"])
		require.Equal(t, true, comp["on_rebound"])
		require.Equal(t, true, comp["cleanup_on_start"])
		require.EqualValues(t, 125, comp["rebound_needed_threshold_mib"])
		require.EqualValues(t, 25, comp["rebound_trigger_threshold_mib"])
		require.NotContains(t, fs, "fsync")
		require.NotContains(t, fs, "timeout")
		require.NotContains(t, comp, "check_interval")
		require.NotContains(t, comp, "max_transaction_size")
	})

	t.Run("all_options_passed_through", func(t *testing.T) {
		fs, err := translateWith(`      max_size: 262144000
      timeout: 2s
      fsync: true
      compaction:
        on_start: false
        on_rebound: true
        cleanup_on_start: false
        check_interval: 10s
        max_transaction_size: 1024
        rebound_needed_threshold_mib: 100
        rebound_trigger_threshold_mib: 10
`)
		require.NoError(t, err)
		require.EqualValues(t, 262144000, fs["max_size"])
		require.Equal(t, "2s", fs["timeout"])
		require.Equal(t, true, fs["fsync"])
		comp := fs["compaction"].(map[string]any)
		require.Equal(t, false, comp["on_start"])
		require.Equal(t, true, comp["on_rebound"])
		require.Equal(t, false, comp["cleanup_on_start"])
		require.Equal(t, "10s", comp["check_interval"])
		require.EqualValues(t, 1024, comp["max_transaction_size"])
		require.EqualValues(t, 100, comp["rebound_needed_threshold_mib"])
		require.EqualValues(t, 10, comp["rebound_trigger_threshold_mib"])
	})
}
