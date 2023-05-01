package main

import (
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/testing/ess"
)

func main() {
	essApiKey := os.Getenv("ESS_API_KEY") // Assumes QA environment
	cfg := ess.Config{ApiKey: essApiKey}

	client := ess.NewClient(cfg)
	resp, err := client.CreateDeployment(ess.CreateDeploymentRequest{
		Name:    "test-880",
		Region:  "gcp-us-central1",
		Version: "8.8.0-SNAPSHOT",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("%#+v\n", resp)
}
