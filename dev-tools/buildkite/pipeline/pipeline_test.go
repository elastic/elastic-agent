// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipeline

import (
	"strings"
	"testing"
)

func TestNewPipeline(t *testing.T) {
	p := New().
		Env("FOO", "bar").
		Env("BAZ", "qux")

	yaml, err := p.MarshalYAML()
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	yamlStr := string(yaml)
	if !strings.Contains(yamlStr, "FOO") {
		t.Error("expected FOO in output")
	}
	if !strings.Contains(yamlStr, "BAZ") {
		t.Error("expected BAZ in output")
	}
}

func TestCommandStep(t *testing.T) {
	step := CommandWithKey("Test step", "test-step", "echo hello")
	SetAgent(step, GCPAgent(ImageUbuntu2204X86, MachineTypeN2Standard8))
	SetArtifactPaths(step, "build/*.xml", "build/*.html")
	SetRetry(step, 1, true)

	if *step.Label != "Test step" {
		t.Errorf("expected label 'Test step', got %s", *step.Label)
	}

	if *step.Key != "test-step" {
		t.Errorf("expected key 'test-step', got %s", *step.Key)
	}

	if step.Agents == nil {
		t.Fatal("expected agents to be set")
	}

	if step.ArtifactPaths == nil || len(step.ArtifactPaths.StringArray) != 2 {
		t.Error("expected 2 artifact paths")
	}

	if step.Retry == nil {
		t.Fatal("expected retry to be set")
	}
}

func TestGroupStep(t *testing.T) {
	group := GroupWithKey("Test group", "test-group")
	SetGroupDependsOn(group, "previous-step")
	SetGroupNotify(group, "buildkite/test")

	step := Command("Nested step", "echo nested")
	AddGroupStep(group, step)

	if group.Group == nil || *group.Group != "Test group" {
		t.Errorf("expected group label 'Test group'")
	}

	if group.Key == nil || *group.Key != "test-group" {
		t.Errorf("expected key 'test-group', got %v", group.Key)
	}

	if group.Steps == nil || len(*group.Steps) != 1 {
		t.Error("expected 1 step in group")
	}
}

func TestTriggerStep(t *testing.T) {
	trigger := Trigger("Trigger other", "other-pipeline")
	SetTriggerIf(trigger, "build.pull_request.id != null")
	SetTriggerAsync(trigger, true)
	SetTriggerBuild(trigger, "${BUILDKITE_COMMIT}", "${BUILDKITE_BRANCH}", nil)

	if *trigger.Trigger != "other-pipeline" {
		t.Errorf("expected trigger 'other-pipeline', got %s", *trigger.Trigger)
	}

	if *trigger.Label != "Trigger other" {
		t.Errorf("expected label 'Trigger other', got %s", *trigger.Label)
	}

	if trigger.Async == nil || trigger.Async.Bool == nil || !*trigger.Async.Bool {
		t.Error("expected async true")
	}
}

func TestMarshalYAML(t *testing.T) {
	step1 := Command("Test", "echo hello")
	step2 := Command("After wait", "echo after")

	p := New().
		Env("VAULT_PATH", "kv/ci-shared/test").
		Add(step1).
		Wait().
		Add(step2)

	yaml, err := p.MarshalYAML()
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	yamlStr := string(yaml)

	// Check for schema comment
	if !strings.Contains(yamlStr, "yaml-language-server") {
		t.Error("expected schema comment in output")
	}

	// Check for env
	if !strings.Contains(yamlStr, "VAULT_PATH") {
		t.Error("expected VAULT_PATH in output")
	}

	// Check for steps
	if !strings.Contains(yamlStr, "steps") {
		t.Error("expected steps in output")
	}
}

func TestAgentHelpers(t *testing.T) {
	tests := []struct {
		name     string
		agent    Agent
		expected map[string]any
	}{
		{
			name:  "GCP agent",
			agent: GCPAgent("test-image", "n2-standard-8"),
			expected: map[string]any{
				"provider":    "gcp",
				"image":       "test-image",
				"machineType": "n2-standard-8",
			},
		},
		{
			name:  "AWS agent",
			agent: AWSAgent("test-image", "m6g.xlarge"),
			expected: map[string]any{
				"provider":     "aws",
				"image":        "test-image",
				"instanceType": "m6g.xlarge",
			},
		},
		{
			name:  "Orka agent",
			agent: OrkaAgent("test-prefix"),
			expected: map[string]any{
				"provider":    "orka",
				"imagePrefix": "test-prefix",
			},
		},
		{
			name:  "GCP agent with disk",
			agent: GCPAgentWithDisk("test-image", "n2-standard-8", 200, "pd-ssd"),
			expected: map[string]any{
				"provider":    "gcp",
				"image":       "test-image",
				"machineType": "n2-standard-8",
				"diskSizeGb":  200,
				"disk_type":   "pd-ssd",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.expected {
				if tt.agent[k] != v {
					t.Errorf("expected %s=%v, got %v", k, v, tt.agent[k])
				}
			}
		})
	}
}

func TestPluginHelpers(t *testing.T) {
	t.Run("VaultDockerLogin", func(t *testing.T) {
		source, config := PluginVaultDockerLogin()
		if !strings.Contains(source, "vault-docker-login") {
			t.Errorf("expected vault-docker-login in source, got %s", source)
		}
		if config["secret_path"] == nil {
			t.Error("expected secret_path in config")
		}
	})

	t.Run("VaultSecrets", func(t *testing.T) {
		source, config := PluginVaultSecrets("kv/path", "field", "ENV_VAR")
		if !strings.Contains(source, "vault-secrets") {
			t.Errorf("expected vault-secrets in source, got %s", source)
		}
		if config["path"] != "kv/path" {
			t.Errorf("expected path 'kv/path', got %v", config["path"])
		}
	})

	t.Run("JunitAnnotate", func(t *testing.T) {
		source, _ := PluginJunitAnnotate("**/*.xml")
		if !strings.Contains(source, "junit-annotate") {
			t.Errorf("expected junit-annotate in source, got %s", source)
		}
	})
}

func TestMatrixConfiguration(t *testing.T) {
	step := Command("Matrix test", "echo {{matrix.os}} {{matrix.version}}")
	SetMatrix(step, map[string][]string{
		"os":      {"linux", "windows"},
		"version": {"1.0", "2.0"},
	})

	if step.Matrix == nil {
		t.Fatal("expected matrix to be set")
	}
}

func TestSimpleMatrix(t *testing.T) {
	step := Command("Simple matrix", "echo {{matrix}}")
	SetSimpleMatrix(step, []string{"a", "b", "c"})

	if step.Matrix == nil {
		t.Fatal("expected matrix to be set")
	}
	if step.Matrix.MatrixElementList == nil || len(*step.Matrix.MatrixElementList) != 3 {
		t.Error("expected 3 matrix values")
	}
}

func TestCompare(t *testing.T) {
	generated := []byte(`steps:
  - command: echo hello
    label: Test
`)
	expected := []byte(`steps:
  - command: echo hello
    label: Test
`)

	result, err := Compare(generated, expected)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}

	if !result.Equal {
		t.Errorf("expected pipelines to be equal, diff: %s", result.Diff)
	}
}

func TestCompareDifferent(t *testing.T) {
	generated := []byte(`steps:
  - command: echo hello
    label: Test
`)
	expected := []byte(`steps:
  - command: echo world
    label: Test
`)

	result, err := Compare(generated, expected)
	if err != nil {
		t.Fatalf("compare failed: %v", err)
	}

	if result.Equal {
		t.Error("expected pipelines to be different")
	}

	if result.Diff == "" {
		t.Error("expected diff to be non-empty")
	}
}

func TestInputStep(t *testing.T) {
	input := Input("Build parameters")
	SetInputIf(input, `build.env("MANIFEST_URL") == null`)
	AddInputField(input, "MANIFEST_URL", "MANIFEST_URL", "", "Link to the build manifest", true)
	AddSelectField(input, "Verbose", "VERBOSE", "Enable verbose output", false,
		SelectOption{Label: "Yes", Value: "1"},
		SelectOption{Label: "No", Value: "0"},
	)

	if input.Input == nil || *input.Input != "Build parameters" {
		t.Error("expected input 'Build parameters'")
	}

	if input.Fields == nil || len(*input.Fields) != 2 {
		t.Error("expected 2 fields")
	}
}

func TestDependsOnWithFailure(t *testing.T) {
	step := Command("Test", "echo test")
	SetDependsOnWithFailure(step,
		DependsOnDep{Step: "step-1", AllowFailure: true},
		DependsOnDep{Step: "step-2", AllowFailure: false},
	)

	if step.DependsOn == nil {
		t.Fatal("expected depends_on to be set")
	}
	if step.DependsOn.DependsOnList == nil || len(*step.DependsOn.DependsOnList) != 2 {
		t.Error("expected 2 dependencies")
	}
}

func TestSetNotify(t *testing.T) {
	step := Command("Test", "echo test")
	SetNotify(step, "buildkite/test")

	if step.Notify == nil {
		t.Fatal("expected notify to be set")
	}
	if len(*step.Notify) != 1 {
		t.Error("expected 1 notification")
	}
}

func TestAddPlugin(t *testing.T) {
	step := Command("Test", "echo test")
	AddPlugin(step, "some-plugin#v1.0.0", map[string]any{"key": "value"})
	AddPlugin(step, "another-plugin#v2.0.0", nil)

	if step.Plugins == nil {
		t.Fatal("expected plugins to be set")
	}
	if step.Plugins.PluginsList == nil || len(*step.Plugins.PluginsList) != 2 {
		t.Errorf("expected 2 plugins")
	}
}

func TestWithPluginHelpers(t *testing.T) {
	step := Command("Test", "echo test")
	WithVaultDockerLogin(step)
	WithVaultECKeyProd(step)

	if step.Plugins == nil {
		t.Fatal("expected plugins to be set")
	}
	if step.Plugins.PluginsList == nil || len(*step.Plugins.PluginsList) != 2 {
		t.Errorf("expected 2 plugins")
	}
}

// BenchmarkMarshalYAML benchmarks YAML marshaling.
func BenchmarkMarshalYAML(b *testing.B) {
	p := New().
		Env("VAULT_PATH", VaultPathGCP).
		WithImageEnvVars()

	for i := 0; i < 10; i++ {
		step := Command("Test step", "echo hello")
		SetAgent(step, GCPAgent(ImageUbuntu2204X86, MachineTypeN2Standard8))
		SetArtifactPaths(step, "build/*.xml")
		SetRetryAutomatic(step, 1)
		p.Add(step)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := p.MarshalYAML()
		if err != nil {
			b.Fatal(err)
		}
	}
}
