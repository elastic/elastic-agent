package devmachine

import (
	"context"
	"fmt"
	"log"
	"time"

	compute "google.golang.org/api/compute/v1"
)

func Run(instanceName string, imageName string, zone string) error {
	ctx := context.Background()

	projectID := "elastic-platform-ingest"
	log.Println("Authenticating with GCP...")
	computeService, err := compute.NewService(ctx)
	if err != nil {
		log.Fatalf("Failed to create compute service: %v. \nRun `gcloud auth login` to make it work", err)
	}

	imageProject := "elastic-images-prod"
	machineType := fmt.Sprintf("zones/%s/machineTypes/n1-standard-1", zone)
	sourceImage := fmt.Sprintf("projects/%s/global/images/%s", imageProject, imageName)

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
		Tags: &compute.Tags{
			Items: []string{"http-server", "https-server"},
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

	fmt.Printf("Instance creation initiated: %s\n", op.Name)
	fmt.Printf("Instance name: %s\n", instanceName)

	retriesLimit := 24
	retryCount := 0
	for {
		time.Sleep(5 * time.Second)

		op, err = computeService.ZoneOperations.Get(projectID, zone, op.Name).Context(ctx).Do()
		if err != nil {
			log.Fatalf("Failed to get operation status: %v", err)
		}
		if op.Status != "DONE" {
			fmt.Print(".")
		}
		if op.Status == "DONE" {
			fmt.Println("Instance creation complete!")
			break
		}
		if retryCount == retriesLimit {
			log.Fatalf("Instance creation failed after %d retries", retriesLimit)
		}
		retryCount++
	}

	instanceDetails, err := computeService.Instances.Get(projectID, zone, instanceName).Context(ctx).Do()
	if err != nil {
		log.Fatalf("Failed to get instance details: %v", err)
		return err
	}

	fmt.Printf("Instance created: %s\n", instanceDetails.Name)

	fmt.Printf(
		`SSH into your instance using: 
  gcloud compute ssh --zone "us-central1-a" "%s" --project "elastic-platform-ingest"
	`, instanceName)

	return nil
}
