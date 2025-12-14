// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package pipeline

import (
	"github.com/buildkite/buildkite-sdk/sdk/go/sdk/buildkite"
)

// Re-export SDK types for convenience
type (
	CommandStep = buildkite.CommandStep
	GroupStep   = buildkite.GroupStep
	TriggerStep = buildkite.TriggerStep
	InputStep   = buildkite.InputStep
	BlockStep   = buildkite.BlockStep
	WaitStep    = buildkite.WaitStep
)

// Command creates a new command step with the given label and command.
func Command(label, command string) *buildkite.CommandStep {
	return &buildkite.CommandStep{
		Label: Ptr(label),
		Command: &buildkite.CommandStepCommand{
			String: Ptr(command),
		},
	}
}

// CommandWithKey creates a new command step with label, key, and command.
func CommandWithKey(label, key, command string) *buildkite.CommandStep {
	return &buildkite.CommandStep{
		Label: Ptr(label),
		Key:   Ptr(key),
		Command: &buildkite.CommandStepCommand{
			String: Ptr(command),
		},
	}
}

// Group creates a new group step with the given label.
func Group(label string) *buildkite.GroupStep {
	return &buildkite.GroupStep{
		Group: Ptr(label),
	}
}

// GroupWithKey creates a new group step with label and key.
func GroupWithKey(label, key string) *buildkite.GroupStep {
	return &buildkite.GroupStep{
		Group: Ptr(label),
		Key:   Ptr(key),
	}
}

// Trigger creates a new trigger step for the given pipeline.
func Trigger(label, pipelineSlug string) *buildkite.TriggerStep {
	return &buildkite.TriggerStep{
		Label:   Ptr(label),
		Trigger: Ptr(pipelineSlug),
	}
}

// Input creates a new input step with the given prompt.
func Input(prompt string) *buildkite.InputStep {
	return &buildkite.InputStep{
		Input: Ptr(prompt),
	}
}

// Block creates a new block step with the given label.
func Block(label string) *buildkite.BlockStep {
	return &buildkite.BlockStep{
		Block: Ptr(label),
	}
}

// SetAgent sets the agent configuration on a command step.
func SetAgent(step *buildkite.CommandStep, agent Agent) *buildkite.CommandStep {
	agentsObject := buildkite.AgentsObject(agent)
	step.Agents = &buildkite.Agents{
		AgentsObject: &agentsObject,
	}
	return step
}

// SetEnv sets environment variables on a command step.
func SetEnv(step *buildkite.CommandStep, env map[string]string) *buildkite.CommandStep {
	envMap := make(buildkite.Env, len(env))
	for k, v := range env {
		envMap[k] = v
	}
	step.Env = &envMap
	return step
}

// AddEnv adds a single environment variable to a command step.
func AddEnv(step *buildkite.CommandStep, key, value string) *buildkite.CommandStep {
	if step.Env == nil {
		envMap := make(buildkite.Env)
		step.Env = &envMap
	}
	(*step.Env)[key] = value
	return step
}

// SetArtifactPaths sets artifact paths on a command step.
func SetArtifactPaths(step *buildkite.CommandStep, paths ...string) *buildkite.CommandStep {
	step.ArtifactPaths = &buildkite.CommandStepArtifactPaths{
		StringArray: paths,
	}
	return step
}

// SetRetry sets retry configuration on a command step.
func SetRetry(step *buildkite.CommandStep, automaticLimit int, manualAllowed bool) *buildkite.CommandStep {
	step.Retry = &buildkite.CommandStepRetry{}

	if automaticLimit > 0 {
		step.Retry.Automatic = &buildkite.CommandStepAutomaticRetry{
			AutomaticRetry: &buildkite.AutomaticRetry{
				Limit: Ptr(automaticLimit),
			},
		}
	}

	if manualAllowed {
		step.Retry.Manual = &buildkite.CommandStepManualRetry{
			CommandStepManualRetryObject: &buildkite.CommandStepManualRetryObject{
				Allowed: &buildkite.CommandStepManualRetryObjectAllowed{
					Bool: Ptr(true),
				},
			},
		}
	}

	return step
}

// SetRetryAutomatic sets automatic retry on a command step.
func SetRetryAutomatic(step *buildkite.CommandStep, limit int) *buildkite.CommandStep {
	if step.Retry == nil {
		step.Retry = &buildkite.CommandStepRetry{}
	}
	step.Retry.Automatic = &buildkite.CommandStepAutomaticRetry{
		AutomaticRetry: &buildkite.AutomaticRetry{
			Limit: Ptr(limit),
		},
	}
	return step
}

// SetRetryManual enables manual retry on a command step.
func SetRetryManual(step *buildkite.CommandStep) *buildkite.CommandStep {
	if step.Retry == nil {
		step.Retry = &buildkite.CommandStepRetry{}
	}
	step.Retry.Manual = &buildkite.CommandStepManualRetry{
		CommandStepManualRetryObject: &buildkite.CommandStepManualRetryObject{
			Allowed: &buildkite.CommandStepManualRetryObjectAllowed{
				Bool: Ptr(true),
			},
		},
	}
	return step
}

// SetMatrix sets a matrix configuration on a command step.
func SetMatrix(step *buildkite.CommandStep, setup map[string][]string) *buildkite.CommandStep {
	matrixSetup := make(buildkite.MatrixSetupObject, len(setup))
	for k, v := range setup {
		elements := make([]buildkite.MatrixElement, len(v))
		for i, val := range v {
			elements[i] = buildkite.MatrixElement{String: Ptr(val)}
		}
		matrixSetup[k] = elements
	}
	step.Matrix = &buildkite.Matrix{
		MatrixObject: &buildkite.MatrixObject{
			Setup: &buildkite.MatrixSetup{
				MatrixSetup: &matrixSetup,
			},
		},
	}
	return step
}

// SetSimpleMatrix sets a simple (single-dimension) matrix on a command step.
func SetSimpleMatrix(step *buildkite.CommandStep, values []string) *buildkite.CommandStep {
	elements := make(buildkite.MatrixElementList, len(values))
	for i, v := range values {
		elements[i] = buildkite.MatrixElement{String: Ptr(v)}
	}
	step.Matrix = &buildkite.Matrix{
		MatrixElementList: &elements,
	}
	return step
}

// SetBranches sets branch filter on a command step.
func SetBranches(step *buildkite.CommandStep, branches string) *buildkite.CommandStep {
	step.Branches = &buildkite.Branches{
		String: Ptr(branches),
	}
	return step
}

// SetIf sets a conditional expression on a command step.
func SetIf(step *buildkite.CommandStep, condition string) *buildkite.CommandStep {
	step.If = Ptr(condition)
	return step
}

// SetDependsOn sets step dependencies on a command step.
// Always uses array format for consistency with YAML files.
func SetDependsOn(step *buildkite.CommandStep, keys ...string) *buildkite.CommandStep {
	items := make(buildkite.DependsOnList, len(keys))
	for i, k := range keys {
		items[i] = buildkite.DependsOnListItem{
			String: Ptr(k),
		}
	}
	step.DependsOn = &buildkite.DependsOn{
		DependsOnList: &items,
	}
	return step
}

// SetDependsOnWithFailure sets step dependencies that allow failures.
func SetDependsOnWithFailure(step *buildkite.CommandStep, deps ...DependsOnDep) *buildkite.CommandStep {
	items := make(buildkite.DependsOnList, len(deps))
	for i, dep := range deps {
		items[i] = buildkite.DependsOnListItem{
			DependsOnList: &buildkite.DependsOnListObject{
				Step: Ptr(dep.Step),
				AllowFailure: &buildkite.DependsOnListObjectAllowFailure{
					Bool: Ptr(dep.AllowFailure),
				},
			},
		}
	}
	step.DependsOn = &buildkite.DependsOn{
		DependsOnList: &items,
	}
	return step
}

// DependsOnDep represents a step dependency with optional allow_failure.
type DependsOnDep struct {
	Step         string
	AllowFailure bool
}

// SetSoftFail configures soft failure handling on a command step.
func SetSoftFail(step *buildkite.CommandStep, softFail bool) *buildkite.CommandStep {
	step.SoftFail = &buildkite.SoftFail{
		SoftFailEnum: &buildkite.SoftFailEnum{
			Bool: Ptr(softFail),
		},
	}
	return step
}

// SetTimeout sets the timeout in minutes on a command step.
func SetTimeout(step *buildkite.CommandStep, minutes int) *buildkite.CommandStep {
	step.TimeoutInMinutes = Ptr(minutes)
	return step
}

// SetSkip marks a command step as skipped.
func SetSkip(step *buildkite.CommandStep, skip bool) *buildkite.CommandStep {
	step.Skip = &buildkite.Skip{
		Bool: Ptr(skip),
	}
	return step
}

// AddPlugin adds a plugin to a command step.
func AddPlugin(step *buildkite.CommandStep, source string, config map[string]any) *buildkite.CommandStep {
	pluginObj := buildkite.PluginsListObject{source: config}
	plugin := buildkite.PluginsListItem{
		PluginsList: &pluginObj,
	}

	if step.Plugins == nil {
		plugins := buildkite.PluginsList{plugin}
		step.Plugins = &buildkite.Plugins{
			PluginsList: &plugins,
		}
	} else if step.Plugins.PluginsList != nil {
		*step.Plugins.PluginsList = append(*step.Plugins.PluginsList, plugin)
	} else {
		plugins := buildkite.PluginsList{plugin}
		step.Plugins.PluginsList = &plugins
	}
	return step
}

// SetNotify sets GitHub commit status notification on a command step.
func SetNotify(step *buildkite.CommandStep, context string) *buildkite.CommandStep {
	notify := buildkite.CommandStepNotify{
		buildkite.CommandStepNotifyItem{
			NotifyGithubCommitStatus: &buildkite.NotifyGithubCommitStatus{
				GithubCommitStatus: &buildkite.NotifyGithubCommitStatusGithubCommitStatus{
					Context: Ptr(context),
				},
			},
		},
	}
	step.Notify = &notify
	return step
}

// SetParallelism sets the parallelism for a command step.
func SetParallelism(step *buildkite.CommandStep, n int) *buildkite.CommandStep {
	step.Parallelism = Ptr(n)
	return step
}

// AddGroupStep adds a command step to a group.
func AddGroupStep(group *buildkite.GroupStep, step *buildkite.CommandStep) *buildkite.GroupStep {
	item := buildkite.GroupStepsItem{
		CommandStep: step,
	}
	if group.Steps == nil {
		steps := buildkite.GroupSteps{item}
		group.Steps = &steps
	} else {
		*group.Steps = append(*group.Steps, item)
	}
	return group
}

// SetGroupDependsOn sets dependencies on a group step.
// Always uses array format for consistency with YAML files.
func SetGroupDependsOn(group *buildkite.GroupStep, keys ...string) *buildkite.GroupStep {
	items := make(buildkite.DependsOnList, len(keys))
	for i, k := range keys {
		items[i] = buildkite.DependsOnListItem{
			String: Ptr(k),
		}
	}
	group.DependsOn = &buildkite.DependsOn{
		DependsOnList: &items,
	}
	return group
}

// SetGroupNotify sets notification on a group step.
func SetGroupNotify(group *buildkite.GroupStep, context string) *buildkite.GroupStep {
	notify := buildkite.BuildNotify{
		buildkite.BuildNotifyItem{
			NotifyGithubCommitStatus: &buildkite.NotifyGithubCommitStatus{
				GithubCommitStatus: &buildkite.NotifyGithubCommitStatusGithubCommitStatus{
					Context: Ptr(context),
				},
			},
		},
	}
	group.Notify = &notify
	return group
}

// SetTriggerBuild sets build configuration on a trigger step.
func SetTriggerBuild(trigger *buildkite.TriggerStep, commit, branch string, env map[string]string) *buildkite.TriggerStep {
	build := &buildkite.TriggerStepBuild{}
	if commit != "" {
		build.Commit = Ptr(commit)
	}
	if branch != "" {
		build.Branch = Ptr(branch)
	}
	if len(env) > 0 {
		envMap := make(buildkite.Env, len(env))
		for k, v := range env {
			envMap[k] = v
		}
		build.Env = &envMap
	}
	trigger.Build = build
	return trigger
}

// SetTriggerIf sets a conditional expression on a trigger step.
func SetTriggerIf(trigger *buildkite.TriggerStep, condition string) *buildkite.TriggerStep {
	trigger.If = Ptr(condition)
	return trigger
}

// SetTriggerBranches sets branch filter on a trigger step.
func SetTriggerBranches(trigger *buildkite.TriggerStep, branches string) *buildkite.TriggerStep {
	trigger.Branches = &buildkite.Branches{
		String: Ptr(branches),
	}
	return trigger
}

// SetTriggerAsync makes a trigger step asynchronous.
func SetTriggerAsync(trigger *buildkite.TriggerStep, async bool) *buildkite.TriggerStep {
	trigger.Async = &buildkite.TriggerStepAsync{
		Bool: Ptr(async),
	}
	return trigger
}

// AddInputField adds a text field to an input step.
func AddInputField(input *buildkite.InputStep, label, key, defaultVal, hint string, required bool) *buildkite.InputStep {
	field := buildkite.FieldsItem{
		TextField: &buildkite.TextField{
			Text:    Ptr(label),
			Key:     Ptr(key),
			Default: Ptr(defaultVal),
			Hint:    Ptr(hint),
			Required: &buildkite.TextFieldRequired{
				Bool: Ptr(required),
			},
		},
	}

	if input.Fields == nil {
		fields := buildkite.Fields{field}
		input.Fields = &fields
	} else {
		*input.Fields = append(*input.Fields, field)
	}
	return input
}

// AddSelectField adds a select field to an input step.
func AddSelectField(input *buildkite.InputStep, label, key, hint string, required bool, options ...SelectOption) *buildkite.InputStep {
	selectOptions := make([]buildkite.SelectFieldOption, len(options))
	for i, opt := range options {
		selectOptions[i] = buildkite.SelectFieldOption{
			Label: Ptr(opt.Label),
			Value: Ptr(opt.Value),
		}
	}

	field := buildkite.FieldsItem{
		SelectField: &buildkite.SelectField{
			Select:  Ptr(label),
			Key:     Ptr(key),
			Hint:    Ptr(hint),
			Options: selectOptions,
			Required: &buildkite.SelectFieldRequired{
				Bool: Ptr(required),
			},
		},
	}

	if input.Fields == nil {
		fields := buildkite.Fields{field}
		input.Fields = &fields
	} else {
		*input.Fields = append(*input.Fields, field)
	}
	return input
}

// SelectOption represents a select input option.
type SelectOption struct {
	Label string
	Value string
}

// SetInputIf sets a conditional expression on an input step.
func SetInputIf(input *buildkite.InputStep, condition string) *buildkite.InputStep {
	input.If = Ptr(condition)
	return input
}

// SetIfChanged sets if_changed patterns on a command step.
func SetIfChanged(step *buildkite.CommandStep, include ...string) *buildkite.CommandStep {
	step.IfChanged = &buildkite.IfChanged{
		IfChanged: &buildkite.IfChangedObject{
			Include: &buildkite.IfChangedObjectInclude{
				StringArray: include,
			},
		},
	}
	return step
}

// SetTriggerIfChanged sets if_changed patterns on a trigger step.
func SetTriggerIfChanged(trigger *buildkite.TriggerStep, include ...string) *buildkite.TriggerStep {
	trigger.IfChanged = &buildkite.IfChanged{
		IfChanged: &buildkite.IfChangedObject{
			Include: &buildkite.IfChangedObjectInclude{
				StringArray: include,
			},
		},
	}
	return trigger
}

// SetTriggerBuildWithMessage sets build configuration with message on a trigger step.
func SetTriggerBuildWithMessage(trigger *buildkite.TriggerStep, commit, branch, message string, env map[string]string) *buildkite.TriggerStep {
	build := &buildkite.TriggerStepBuild{}
	if commit != "" {
		build.Commit = Ptr(commit)
	}
	if branch != "" {
		build.Branch = Ptr(branch)
	}
	if message != "" {
		build.Message = Ptr(message)
	}
	if len(env) > 0 {
		envMap := make(buildkite.Env, len(env))
		for k, v := range env {
			envMap[k] = v
		}
		build.Env = &envMap
	}
	trigger.Build = build
	return trigger
}

// SetCommands sets multiple commands on a command step using the 'commands' field.
func SetCommands(step *buildkite.CommandStep, commands ...string) *buildkite.CommandStep {
	step.Commands = &buildkite.CommandStepCommand{
		StringArray: commands,
	}
	return step
}

// WaitIf creates a conditional wait step.
func WaitIf(condition string) *buildkite.WaitStep {
	return &buildkite.WaitStep{
		Wait: Ptr(""),
		If:   Ptr(condition),
	}
}

// SetAllowDependencyFailure sets allow_dependency_failure on a command step.
func SetAllowDependencyFailure(step *buildkite.CommandStep, allow bool) *buildkite.CommandStep {
	step.AllowDependencyFailure = &buildkite.AllowDependencyFailure{
		Bool: Ptr(allow),
	}
	return step
}

// SetSoftFailExitStatus sets soft_fail with exit status pattern on a command step.
func SetSoftFailExitStatus(step *buildkite.CommandStep, exitStatus string) *buildkite.CommandStep {
	enumVal := buildkite.SoftFailObjectExitStatusEnum(exitStatus)
	list := buildkite.SoftFailList{
		buildkite.SoftFailObject{
			ExitStatus: &buildkite.SoftFailObjectExitStatus{
				SoftFailObjectExitStatusEnum: &enumVal,
			},
		},
	}
	step.SoftFail = &buildkite.SoftFail{
		SoftFailList: &list,
	}
	return step
}

// SetSkipWithMessage marks a command step as skipped with a reason.
func SetSkipWithMessage(step *buildkite.CommandStep, message string) *buildkite.CommandStep {
	step.Skip = &buildkite.Skip{
		String: Ptr(message),
	}
	return step
}

// SetGroupAllowDependencyFailure sets allow_dependency_failure on a group step.
func SetGroupAllowDependencyFailure(group *buildkite.GroupStep, allow bool) *buildkite.GroupStep {
	group.AllowDependencyFailure = &buildkite.AllowDependencyFailure{
		Bool: Ptr(allow),
	}
	return group
}

// SetGroupIf sets a conditional expression on a group step.
func SetGroupIf(group *buildkite.GroupStep, condition string) *buildkite.GroupStep {
	group.If = Ptr(condition)
	return group
}

// SetKey sets the key on a command step.
func SetKey(step *buildkite.CommandStep, key string) *buildkite.CommandStep {
	step.Key = Ptr(key)
	return step
}
