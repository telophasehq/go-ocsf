package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/telophasehq/go-ocsf/clients/snyk"
	"github.com/telophasehq/go-ocsf/clients/tenable"
	"github.com/telophasehq/go-ocsf/datastore"
	"github.com/telophasehq/go-ocsf/syncers"
	"github.com/telophasehq/go-ocsf/syncers/cloudtrail"
	"github.com/telophasehq/go-ocsf/syncers/gcpauditlog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

func main() {
	isParquet := flag.Bool("parquet", false, "Use parquet format")
	isJSON := flag.Bool("json", false, "Use JSON format")
	bucketName := flag.String("bucket-name", "", "S3 bucket name")
	tableBucketName := flag.String("table-bucket-name", "", "Table bucket name")
	// Sync data.
	syncSnykOption := flag.Bool("sync-snyk", false, "Sync Snyk data.")
	syncTenableOption := flag.Bool("sync-tenable", false, "Sync Tenable data.")
	syncSecurityHubOption := flag.Bool("sync-security-hub", false, "Sync SecurityHub data.")
	syncInspectorOption := flag.Bool("sync-inspector", false, "Sync Inspector data.")
	syncGCPAuditLogOption := flag.Bool("sync-gcp-audit-log", false, "Sync GCP AuditLog data.")
	syncCloudTrailOption := flag.Bool("sync-cloudtrail", false, "Sync CloudTrail data.")
	cloudtrailBucketName := flag.String("cloudtrail-bucket-name", "", "CloudTrail bucket name")
	flag.Parse()

	ctx := context.Background()

	snykAPIKey := os.Getenv("SNYK_API_KEY")
	snykOrganizationID := os.Getenv("SNYK_ORGANIZATION_ID")

	tenableAPIKey := os.Getenv("TENABLE_API_KEY")
	tenableSecretKey := os.Getenv("TENABLE_SECRET_KEY")

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	storageOpts := datastore.StorageOpts{
		IsParquet:      *isParquet,
		IsJSON:         *isJSON,
		BucketName:     *bucketName,
		TableBucketArn: *tableBucketName,
	}

	if *syncSnykOption {
		if snykAPIKey == "" || snykOrganizationID == "" {
			log.Fatal("SNYK_API_KEY and SNYK_ORGANIZATION_ID must be set when --sync-snyk is set")
		}

		if err := syncSnyk(ctx, snykAPIKey, snykOrganizationID, storageOpts); err != nil {
			log.Fatalf("Failed to sync Snyk data: %v", err)
		}
	}

	if *syncTenableOption {
		if tenableAPIKey == "" || tenableSecretKey == "" {
			log.Fatal("TENABLE_API_KEY and TENABLE_SECRET_KEY must be set when --sync-tenable is set")
		}

		if err := syncTenable(ctx, tenableAPIKey, tenableSecretKey, storageOpts); err != nil {
			log.Fatalf("Failed to sync Tenable data: %v", err)
		}
	}

	if *syncSecurityHubOption {
		if err := syncSecurityHub(ctx, storageOpts, cfg); err != nil {
			log.Fatalf("Failed to sync SecurityHub data: %v", err)
		}
	}

	if *syncGCPAuditLogOption {
		if err := syncGCPAuditLog(ctx, storageOpts); err != nil {
			log.Fatalf("Failed to sync GCPAuditLog data: %v", err)
		}
	}

	if *syncInspectorOption {
		if err := inspectorSync(ctx, storageOpts, cfg); err != nil {
			log.Fatalf("Failed to sync Inspector data: %v", err)
		}
	}

	if *syncCloudTrailOption {
		if err := syncCloudTrail(ctx, *cloudtrailBucketName, storageOpts, cfg); err != nil {
			log.Fatalf("Failed to sync CloudTrail data: %v", err)
		}
	}
}

func syncSnyk(ctx context.Context, apiKey, orgID string, storageOpts datastore.StorageOpts) error {
	snykClient, err := snyk.NewClient(apiKey, orgID)
	if err != nil {
		return fmt.Errorf("failed to create Snyk client: %v", err)
	}

	snykSyncer, err := syncers.NewSnykOCSFSyncer(ctx, snykClient, storageOpts)
	if err != nil {
		return fmt.Errorf("failed to create Snyk syncer: %v", err)
	}

	err = snykSyncer.Sync(ctx)
	if err != nil {
		log.Fatalf("Failed to sync Snyk data: %v", err)
	}

	return snykSyncer.Sync(ctx)
}

func inspectorSync(ctx context.Context, storageOpts datastore.StorageOpts, cfg aws.Config) error {
	inspectorClient := inspector2.NewFromConfig(cfg)

	inspectorSyncer, err := syncers.NewInspectorOCSFSyncer(ctx, inspectorClient, storageOpts)
	if err != nil {
		return fmt.Errorf("failed to create Inspector syncer: %v", err)
	}

	return inspectorSyncer.Sync(ctx)
}

func syncTenable(ctx context.Context, apiKey, secretKey string, storageOpts datastore.StorageOpts) error {
	tenableClient, err := tenable.NewClient(apiKey, secretKey)
	if err != nil {
		return fmt.Errorf("failed to create Tenable client: %v", err)
	}

	tenableSyncer, err := syncers.NewTenableOCSFSyncer(ctx, tenableClient, storageOpts)
	if err != nil {
		return fmt.Errorf("failed to create Tenable syncer: %v", err)
	}

	return tenableSyncer.Sync(ctx)
}

func syncSecurityHub(ctx context.Context, storageOpts datastore.StorageOpts, cfg aws.Config) error {
	securityHubClient := securityhub.NewFromConfig(cfg)

	securityHubSyncer, err := syncers.NewSecurityHubOCSFSyncer(ctx, securityHubClient, storageOpts)
	if err != nil {
		return fmt.Errorf("failed to create SecurityHub syncer: %v", err)
	}

	return securityHubSyncer.Sync(ctx)
}

func syncGCPAuditLog(ctx context.Context, storageOpts datastore.StorageOpts) error {
	gcpauditlogSyncer, err := gcpauditlog.NewGCPAuditLogSyncer(ctx, os.Getenv("GCP_PROJECT_ID"), storageOpts)
	if err != nil {
		return fmt.Errorf("failed to create GCPAuditLog syncer: %v", err)
	}

	return gcpauditlogSyncer.Sync(ctx)
}

func syncCloudTrail(ctx context.Context, bucketName string, storageOpts datastore.StorageOpts, cfg aws.Config) error {
	s3Client := s3.NewFromConfig(cfg)

	cloudtrailSyncer, err := cloudtrail.NewSyncer(ctx, s3Client, bucketName, storageOpts)
	if err != nil {
		return fmt.Errorf("failed to create CloudTrail syncer: %v", err)
	}

	return cloudtrailSyncer.Sync(ctx)
}
