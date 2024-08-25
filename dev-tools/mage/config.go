// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/magefile/mage/mg"
)

// ConfigFileType is a bitset that indicates what types of config files to
// generate.
type ConfigFileType uint8

// Config file types.
const (
	ShortConfigType ConfigFileType = 1 << iota
	ReferenceConfigType
	DockerConfigType

	AllConfigTypes ConfigFileType = 0xFF
)

// IsShort return true if ShortConfigType is set.
func (t ConfigFileType) IsShort() bool { return t&ShortConfigType > 0 }

// IsReference return true if ReferenceConfigType is set.
func (t ConfigFileType) IsReference() bool { return t&ReferenceConfigType > 0 }

// IsDocker return true if DockerConfigType is set.
func (t ConfigFileType) IsDocker() bool { return t&DockerConfigType > 0 }

// ConfigFileParams defines the files that make up each config file.
type ConfigFileParams struct {
	Templates                []string // List of files or globs to load.
	ExtraVars                map[string]interface{}
	Short, Reference, Docker ConfigParams
}

// ConfigParams defines config param template
type ConfigParams struct {
	Template string
	Deps     []interface{}
}

// Config generates config files. Set DEV_OS and DEV_ARCH to change the target
// host for the generated configs. Defaults to linux/amd64.
func Config(types ConfigFileType, args ConfigFileParams, targetDir string) error {
	// Short
	if types.IsShort() {
		file := filepath.Join(targetDir, BeatName+".yml")
		if err := makeConfigTemplate(file, 0600, args, ShortConfigType); err != nil {
			return fmt.Errorf("failed making short config: %w", err)
		}
	}

	// Reference
	if types.IsReference() {
		file := filepath.Join(targetDir, BeatName+".reference.yml")
		if err := makeConfigTemplate(file, 0644, args, ReferenceConfigType); err != nil {
			return fmt.Errorf("failed making reference config: %w", err)
		}
	}

	// Docker
	if types.IsDocker() {
		file := filepath.Join(targetDir, BeatName+".docker.yml")
		if err := makeConfigTemplate(file, 0600, args, DockerConfigType); err != nil {
			return fmt.Errorf("failed making docker config: %w", err)
		}
	}

	return nil
}

func makeConfigTemplate(destination string, mode os.FileMode, confParams ConfigFileParams, typ ConfigFileType) error {
	// Determine what type to build and set some parameters.
	var confFile ConfigParams
	var tmplParams map[string]interface{}
	switch typ {
	case ShortConfigType:
		confFile = confParams.Short
		tmplParams = map[string]interface{}{}
	case ReferenceConfigType:
		confFile = confParams.Reference
		tmplParams = map[string]interface{}{"Reference": true}
	case DockerConfigType:
		confFile = confParams.Docker
		tmplParams = map[string]interface{}{"Docker": true}
	default:
		panic(fmt.Errorf("invalid config file type: %v", typ))
	}

	// Build the dependencies.
	mg.SerialDeps(confFile.Deps...)

	// Set variables that are available in templates.
	// Rather than adding more "ExcludeX"/"UseX" options consider overwriting
	// one of the libbeat templates in your project by adding a file with the
	// same name to your _meta/config directory.
	params := map[string]interface{}{
		"GOOS":                           EnvOr("DEV_OS", "linux"),
		"GOARCH":                         EnvOr("DEV_ARCH", "amd64"),
		"BeatLicense":                    BeatLicense,
		"Reference":                      false,
		"Docker":                         false,
		"ExcludeConsole":                 false,
		"ExcludeFileOutput":              false,
		"ExcludeKafka":                   false,
		"ExcludeLogstash":                false,
		"ExcludeRedis":                   false,
		"UseObserverProcessor":           false,
		"UseDockerMetadataProcessor":     true,
		"UseKubernetesMetadataProcessor": false,
		"ExcludeDashboards":              false,
	}
	params = joinMaps(params, confParams.ExtraVars, tmplParams)
	tmpl := template.New("config").Option("missingkey=error")
	funcs := joinMaps(FuncMap, template.FuncMap{
		"header":    header,
		"subheader": subheader,
		"indent":    indent,
		// include is necessary because you cannot pipe 'template' to a function
		// since 'template' is an action. This allows you to include a
		// template and indent it (e.g. {{ include "x.tmpl" . | indent 4 }}).
		"include": func(name string, data interface{}) (string, error) {
			buf := bytes.NewBuffer(nil)
			if err := tmpl.ExecuteTemplate(buf, name, data); err != nil {
				return "", err
			}
			return buf.String(), nil
		},
	})
	tmpl = tmpl.Funcs(funcs)

	fmt.Printf(">> Building %v for %v/%v\n", destination, params["GOOS"], params["GOARCH"])
	var err error
	for _, templateGlob := range confParams.Templates {
		if tmpl, err = tmpl.ParseGlob(templateGlob); err != nil {
			return fmt.Errorf("failed to parse config templates in %q: %w", templateGlob, err)
		}
	}

	data, err := os.ReadFile(confFile.Template)
	if err != nil {
		return fmt.Errorf("failed to read config template %q: %w", confFile.Template, err)
	}

	tmpl, err = tmpl.Parse(string(data))
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	out, err := os.OpenFile(CreateDir(destination), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if err = tmpl.Execute(out, EnvMap(params)); err != nil {
		return fmt.Errorf("failed building %v: %w", destination, err)
	}

	return nil
}

func header(title string) string {
	return makeHeading(title, "=")
}

func subheader(title string) string {
	return makeHeading(title, "-")
}

var nonWhitespaceRegex = regexp.MustCompile(`(?m)(^.*\S.*$)`)

// indent pads all non-whitespace lines with the number of spaces specified.
func indent(spaces int, content string) string {
	pad := strings.Repeat(" ", spaces)
	return nonWhitespaceRegex.ReplaceAllString(content, pad+"$1")
}

func makeHeading(title, separator string) string {
	const line = 80
	leftEquals := (line - len("# ") - len(title) - 2*len(" ")) / 2
	rightEquals := leftEquals + len(title)%2
	return "# " + strings.Repeat(separator, leftEquals) + " " + title + " " + strings.Repeat(separator, rightEquals)
}
