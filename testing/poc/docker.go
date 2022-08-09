package poc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	devtools "github.com/elastic/elastic-agent/dev-tools/mage"
	"github.com/google/uuid"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	tc "github.com/testcontainers/testcontainers-go"
)

func StackUp() (error, string) {
	rootDir := ElasticAgentDirectory("")
	composeFile := filepath.Join(rootDir, "testing", "poc", "docker-compose-es.yml")
	composeFile1 := filepath.Join(rootDir, "testing", "poc", "docker-compose.yml")
	composeFilePaths := []string{composeFile, composeFile1}
	identifier := strings.ToLower(uuid.New().String())
	compose := tc.NewLocalDockerCompose(composeFilePaths, identifier)
	execError := compose.
		WithCommand([]string{"up", "-d"}).
		WithEnv(map[string]string{}).
		Invoke()
	err := execError.Error
	if err != nil {
		return fmt.Errorf("Could not run compose file: %v - %v", composeFilePaths, err), identifier
	}
	return nil, identifier
}

func ElasticSearchUp() (error, string) {
	rootDir := ElasticAgentDirectory("")
	composeFile := filepath.Join(rootDir, "testing", "poc", "docker-compose-es.yml")
	composeFilePaths := []string{composeFile}
	identifier := strings.ToLower(uuid.New().String())
	compose := tc.NewLocalDockerCompose(composeFilePaths, identifier)
	execError := compose.
		WithCommand([]string{"up", "-d"}).
		WithEnv(map[string]string{
			"key1": "value1",
			"key2": "value2",
		}).
		Invoke()
	err := execError.Error
	if err != nil {
		return fmt.Errorf("Could not run compose file: %v - %v", composeFilePaths, err), identifier
	}
	return nil, identifier
}

func StackDown(identifier string) error {
	rootDir := ElasticAgentDirectory("")
	composeFile := filepath.Join(rootDir, "testing", "poc", "docker-compose-es.yml")
	composeFile1 := filepath.Join(rootDir, "testing", "poc", "docker-compose.yml")
	composeFilePaths := []string{composeFile, composeFile1}

	compose := tc.NewLocalDockerCompose(composeFilePaths, identifier)
	execError := compose.Down()
	err := execError.Error
	if err != nil {
		return fmt.Errorf("Could not run compose file: %v - %v", composeFilePaths, err)
	}
	return nil
}

func ElasticAgentUp() error {
	os.Setenv("DEV", "true")
	os.Setenv("DEV", "true")
	RunGo("version")
	RunGo("env")
	devtools.DevBuild = true
	devtools.PLATFORMS = "windows/amd64"
	buildArgs := devtools.DefaultBuildArgs()
	buildArgs.Name = "elastic-agent"
	buildArgs.OutputDir = filepath.Join(ElasticAgentDirectory(""), "build", "test")
	injectBuildVars(buildArgs.Vars)
	err := devtools.Build(buildArgs)
	if err != nil {
		return err
	}
	input, err := ioutil.ReadFile(filepath.Join(ElasticAgentDirectory(""), "_meta", "elastic-agent.yml"))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(ElasticAgentDirectory(""), "build", "test", "elastic-agent.yml"), input, 0644)
	if err != nil {
		return err
	}
	command := exec.Command(filepath.Join(buildArgs.OutputDir, "elastic-agent.exe"), "run")

	// set var to get the output
	var out bytes.Buffer

	// set the output to our variable
	command.Stdout = &out
	err = command.Run()
	if err != nil {
		log.Println(err)
	}

	fmt.Println(out.String())
	return nil
}
func RunGo(args ...string) error {
	return sh.RunV(mg.GoCmd(), args...)
}

func injectBuildVars(m map[string]string) {
	vars := make(map[string]string)
	vars["github.com/elastic/elastic-agent/internal/pkg/release.snapshot"] = "true"
	vars["github.com/elastic/elastic-agent/internal/pkg/release.allowEmptyPgp"] = "true"
	vars["github.com/elastic/elastic-agent/internal/pkg/release.allowUpgrade"] = "true"
	for k, v := range vars {
		m[k] = v
	}
}

func ElasticAgentDirectory(pwd string) string {
	if pwd == "" {
		pwd, _ = os.Getwd()
	} else {
		pwd = filepath.Dir(pwd)
	}
	base := filepath.Base(pwd)

	if base == "elastic-agent" {
		return pwd
	}
	return ElasticAgentDirectory(pwd)
}
