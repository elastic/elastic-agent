package poc

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	tc "github.com/testcontainers/testcontainers-go"
)

func StackUp() (error, string) {
	composeFile := filepath.Join("docker-compose.yml")
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
	composeFile := filepath.Join("docker-compose.yml")
	composeFilePaths := []string{composeFile}

	compose := tc.NewLocalDockerCompose(composeFilePaths, identifier)
	execError := compose.Down()
	err := execError.Error
	if err != nil {
		return fmt.Errorf("Could not run compose file: %v - %v", composeFilePaths, err)
	}
	return nil
}
