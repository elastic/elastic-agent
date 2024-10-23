// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package devmachine

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	compute "google.golang.org/api/compute/v1"
)

const (
	ZONE_TEMPLATE  = "zones/%s/machineTypes/n1-standard-4"
	IMAGE_TEMPLATE = "projects/%s/global/images/%s"
	DEFAULT_IMAGE  = "family/platform-ingest-elastic-agent-ubuntu-2204"
	DEFAULT_ZONE   = "us-central1-a"
)

func Run(instanceName string) error {
	machineImage := os.Getenv("MACHINE_IMAGE")
	if machineImage == "" {
		machineImage = DEFAULT_IMAGE
	}
	zone := os.Getenv("ZONE")
	if zone == "" {
		zone = DEFAULT_ZONE
	}

	ctx := context.Background()
	log.Println(">> Creating devmachine")
	projectID := "elastic-platform-ingest"
	log.Println("Authenticating with GCP...")
	computeService, err := compute.NewService(ctx)
	if err != nil {
		log.Fatalf("Failed to create compute service: %v. \nRun `gcloud auth login` to make it work", err)
	}

	imageProject := "elastic-images-prod"
	machineType := fmt.Sprintf(ZONE_TEMPLATE, zone)
	sourceImage := fmt.Sprintf(IMAGE_TEMPLATE, imageProject, machineImage)

	instance := &compute.Instance{
		Name:        instanceName,
		MachineType: machineType,
		Disks: []*compute.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				InitializeParams: &compute.AttachedDiskInitializeParams{
					SourceImage: sourceImage,
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{
				AccessConfigs: []*compute.AccessConfig{
					{
						Name: "External NAT",
						Type: "ONE_TO_ONE_NAT",
					},
				},
				Network: "global/networks/default", // Use default network
			},
		},
		Labels: map[string]string{
			"division": "engineering",
			"org":      "platform-ingest",
			"project":  "elastic-agent",
			"team":     "elastic-agent",
			"max-age":  "6h",
		},
		Scheduling: &compute.Scheduling{
			MaxRunDuration: &compute.Duration{
				Seconds: 6 * 60 * 60, // 6 hours
				Nanos:   0,
			},
			InstanceTerminationAction: "DELETE",
		},
	}

	op, err := computeService.Instances.Insert(projectID, zone, instance).Context(ctx).Do()
	if err != nil {
		log.Fatalf("Failed to create instance: %v", err)
	}

	log.Printf("Instance creation initiated: %s\n", op.Name)
	log.Printf("Instance name: %s\n", instanceName)

	retriesLimit := 24
	retryCount := 0
	for {
		op, err = computeService.ZoneOperations.Get(projectID, zone, op.Name).Context(ctx).Do()
		if err != nil {
			log.Fatalf("Failed to get operation status: %v", err)
		}
		if op.Status != "DONE" {
			log.Print(".")
		}
		if op.Status == "DONE" {
			log.Println("Instance creation complete!")
			break
		}
		if retryCount == retriesLimit {
			log.Fatalf("Instance creation failed after %d retries", retriesLimit)
		}
		time.Sleep(5 * time.Second)
		retryCount++
	}

	instanceDetails, err := computeService.Instances.Get(projectID, zone, instanceName).Context(ctx).Do()
	if err != nil {
		log.Fatalf("Failed to get instance details: %v", err)
		return err
	}

	log.Printf("Instance created: %s\n", instanceDetails.Name)

	log.Printf(
		`SSH into your instance using: 
  gcloud compute ssh --zone "%s" buildkite-agent@%s --project "elastic-platform-ingest"
	Once you are in the instance, type "bash" to start a bash shell.
	`, zone, instanceName)

	log.Printf(
		`Copy files to your instance using: 
  gcloud compute scp --recurse --compress --zone "%s"  buildkite-agent%s:~ [your_file/your_current_dir] --project "elastic-platform-ingest"
	TIP: Better use git on the remote machine.
	`, zone, instanceName)

	return nil
}
