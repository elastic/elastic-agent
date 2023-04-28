package define

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"gopkg.in/yaml.v2"
)

var setRequirements *Requirements
var setRequirementsOnce sync.Once

func Require(t *testing.T, req Requirements) {
	setRequirementsOnce.Do(func() {
		req, err := loadRequirements()
		if err != nil {
			panic(err)
		}
		setRequirements = &req
	})

}

func loadRequirements() (Requirements, error) {
	raw := os.Getenv("AGENT_TEST_DEFINE_REQUIREMENTS")
	if raw == "" {
		return Requirements{}, errors.New("AGENT_TEST_DEFINE_REQUIREMENTS not defined")
	}
	var req Requirements
	err := yaml.Unmarshal([]byte(raw), &req)
	if err != nil {
		return Requirements{}, fmt.Errorf("failed to unmarshal AGENT_TEST_DEFINE_REQUIREMENTS: %w", err)
	}
	return req, nil
}
