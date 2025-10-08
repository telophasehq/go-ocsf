package syncers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/samsarahq/go/oops"
	"github.com/telophasehq/go-ocsf/datastore"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_4_0"
)

type SecurityHubOCSFSyncer struct {
	securityHubClient *securityhub.Client
	datastore         datastore.Datastore[ocsf.VulnerabilityFinding]
}

// NewSecurityHubOCSFSyncer creates a new SecurityHubOCSFSyncer
// It initializes the SecurityHub client and datastore.
func NewSecurityHubOCSFSyncer(ctx context.Context, securityHubClient *securityhub.Client, storageOpts datastore.StorageOpts) (DataSync, error) {
	dataStoreInst, err := datastore.SetupStorage[ocsf.VulnerabilityFinding](ctx, storageOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to setup datastore: %w", err)
	}

	return &SecurityHubOCSFSyncer{
		securityHubClient: securityHubClient,
		datastore:         dataStoreInst,
	}, nil
}

// Sync synchronizes SecurityHub data with the OCSF datastore
// It fetches all findings from SecurityHub, builds OCSF findings, and saves them to the datastore.
func (s *SecurityHubOCSFSyncer) Sync(ctx context.Context) error {
	slog.Info("syncing SecurityHub data")

	var nextToken *string
	for {
		securityHubFindingsOutput, err := s.securityHubClient.GetFindings(
			ctx,
			&securityhub.GetFindingsInput{
				MaxResults: aws.Int32(100),
				SortCriteria: []types.SortCriterion{
					{
						Field:     aws.String("LastObservedAt"),
						SortOrder: types.SortOrderDescending,
					},
				},
				NextToken: nextToken,
			},
		)
		if err != nil {
			return oops.Wrapf(err, "failed to list all findings")
		}

		slog.Info("SecurityHub findings", "num_findings", len(securityHubFindingsOutput.Findings))

		var findingsToSave []ocsf.VulnerabilityFinding
		for _, securityHubFinding := range securityHubFindingsOutput.Findings {
			finding, err := s.ToOCSF(ctx, securityHubFinding)
			if err != nil {
				return oops.Wrapf(err, "failed to build OCSF finding")
			}

			findingsToSave = append(findingsToSave, finding)
		}

		err = s.datastore.Save(ctx, findingsToSave)
		if err != nil {
			return oops.Wrapf(err, "failed to save findings")
		}

		if securityHubFindingsOutput.NextToken == nil {
			break
		}

		nextToken = securityHubFindingsOutput.NextToken
	}

	slog.Info("Finished SecurityHub sync")
	return nil
}

// ToOCSF converts a SecurityHub finding into an OCSF vulnerability finding.
func (s *SecurityHubOCSFSyncer) ToOCSF(ctx context.Context, securityHubFinding types.AwsSecurityFinding) (ocsf.VulnerabilityFinding, error) {
	severity, severityID := mapSecurityHubSeverity(securityHubFinding.Severity)
	status, statusID := mapSecurityHubStatus(securityHubFinding.Workflow)

	var createdAt *time.Time
	if securityHubFinding.CreatedAt != nil {
		parsedTime, err := time.Parse(time.RFC3339, *securityHubFinding.CreatedAt)
		if err == nil {
			createdAt = &parsedTime
		}
	}

	var endTime *time.Time
	if status == "Closed" {
		if securityHubFinding.UpdatedAt != nil {
			parsedTime, err := time.Parse(time.RFC3339, *securityHubFinding.UpdatedAt)
			if err == nil {
				endTime = &parsedTime
			}
		}
	}

	vendorName := "AWS"
	// SecurityHub Vulnerability doesn't have Exploitability field, so we'll need to check differently
	// or set a default value
	exploitAvailable := false

	var fixAvailable bool
	if securityHubFinding.Remediation != nil && securityHubFinding.Remediation.Recommendation != nil {
		fixAvailable = true
	}

	var remediation *ocsf.Remediation
	if securityHubFinding.Remediation != nil {
		var description string
		if securityHubFinding.Remediation.Recommendation != nil && securityHubFinding.Remediation.Recommendation.Text != nil {
			description = *securityHubFinding.Remediation.Recommendation.Text
		}

		var references []string
		if securityHubFinding.Remediation.Recommendation != nil && securityHubFinding.Remediation.Recommendation.Url != nil {
			references = append(references, *securityHubFinding.Remediation.Recommendation.Url)
		}

		remediation = &ocsf.Remediation{
			Desc:       description,
			References: references,
		}
	}

	var title string
	if securityHubFinding.Title != nil {
		title = *securityHubFinding.Title
	}

	// Convert UpdatedAt string to time.Time for LastSeenTime
	var lastSeenTime *time.Time
	if securityHubFinding.UpdatedAt != nil {
		parsedTime, err := time.Parse(time.RFC3339, *securityHubFinding.UpdatedAt)
		if err == nil {
			lastSeenTime = &parsedTime
		}
	}

	var createdTimeInt int64
	if createdAt != nil {
		createdTimeInt = createdAt.UnixMilli()
	}

	var lastSeenTimeInt int64
	if lastSeenTime != nil {
		lastSeenTimeInt = lastSeenTime.UnixMilli()
	}

	vulnerabilities := []ocsf.VulnerabilityDetails{
		{
			Cwe:                mapSecurityHubCWE(securityHubFinding),
			Cve:                mapSecurityHubCVE(securityHubFinding),
			Desc:               securityHubFinding.Description,
			Title:              &title,
			Severity:           &severity,
			IsExploitAvailable: &exploitAvailable,
			FirstSeenTime:      createdTimeInt,
			IsFixAvailable:     &fixAvailable,
			LastSeenTime:       lastSeenTimeInt,
			VendorName:         &vendorName,
			Remediation:        remediation,
		},
	}

	var activityID int32
	var activityName string
	var typeUID int64
	var typeName string
	var eventTime time.Time
	className := "Vulnerability Finding"
	categoryUID := int32(2)
	categoryName := "Findings"
	classUID := int32(2002)

	if securityHubFinding.UpdatedAt == securityHubFinding.CreatedAt {
		activityID = int32(1)
		activityName = "Create"
		typeUID = int64(classUID)*100 + int64(activityID)
		typeName = "Vulnerability Finding: Create"
		eventTime = *createdAt
	} else if status == "Closed" {
		activityID = int32(3)
		activityName = "Close"
		typeUID = int64(classUID)*100 + int64(activityID)
		typeName = "Vulnerability Finding: Close"
		eventTime = *endTime
	} else {
		activityID = int32(2)
		activityName = "Update"
		typeUID = int64(classUID)*100 + int64(activityID)
		typeName = "Vulnerability Finding: Update"
		parsedTime, err := time.Parse(time.RFC3339, *securityHubFinding.UpdatedAt)
		if err != nil {
			return ocsf.VulnerabilityFinding{}, oops.Wrapf(err, "failed to parse time")
		}
		eventTime = parsedTime
	}

	productName := "SecurityHub"

	metadata := ocsf.Metadata{
		Product: ocsf.Product{
			Name:       &productName,
			VendorName: &vendorName,
		},
		Version: "1.4.0",
	}

	var modifiedTime *time.Time
	if securityHubFinding.UpdatedAt != nil {
		parsedTime, err := time.Parse(time.RFC3339, *securityHubFinding.UpdatedAt)
		if err == nil {
			modifiedTime = &parsedTime
		}
	}

	var modifiedTimeInt int64
	if modifiedTime != nil {
		modifiedTimeInt = modifiedTime.UnixMilli()
	}

	var endTimeInt int64
	if endTime != nil {
		endTimeInt = endTime.UnixMilli()
	}

	findingInfo := ocsf.FindingInformation{
		Uid:           *securityHubFinding.Id,
		Title:         securityHubFinding.Title,
		Desc:          securityHubFinding.Description,
		CreatedTime:   createdTimeInt,
		FirstSeenTime: createdTimeInt,
		LastSeenTime:  lastSeenTimeInt,
		ModifiedTime:  modifiedTimeInt,
		DataSources:   []string{"securityhub"},
		Types:         []string{"Vulnerability"},
	}

	finding := ocsf.VulnerabilityFinding{
		Time:            eventTime.UnixMilli(),
		StartTime:       createdTimeInt,
		EndTime:         endTimeInt,
		ActivityId:      activityID,
		ActivityName:    &activityName,
		CategoryUid:     categoryUID,
		CategoryName:    &categoryName,
		ClassUid:        classUID,
		ClassName:       &className,
		Message:         securityHubFinding.Description,
		Metadata:        metadata,
		Resources:       mapSecurityHubResources(securityHubFinding),
		Status:          &status,
		StatusId:        &statusID,
		TypeUid:         typeUID,
		TypeName:        &typeName,
		Vulnerabilities: vulnerabilities,
		FindingInfo:     findingInfo,
		SeverityId:      int32(severityID),
		Severity:        &severity,
	}

	return finding, nil
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

func mapSecurityHubSeverity(severity *types.Severity) (string, int) {
	if severity == nil {
		return "unknown", 0
	}

	// SeverityLabel is an enum, not a pointer
	switch severity.Label {
	case types.SeverityLabelInformational:
		return "informational", 1
	case types.SeverityLabelLow:
		return "low", 2
	case types.SeverityLabelMedium:
		return "medium", 3
	case types.SeverityLabelHigh:
		return "high", 4
	case types.SeverityLabelCritical:
		return "critical", 5
	default:
		return "unknown", 0
	}
}

func mapSecurityHubStatus(workflow *types.Workflow) (string, int32) {
	if workflow == nil {
		return "open", 1
	}

	// WorkflowStatus is an enum, not a pointer
	switch workflow.Status {
	case types.WorkflowStatusNew, types.WorkflowStatusNotified:
		return "open", 1
	case types.WorkflowStatusSuppressed:
		return "suppressed", 3
	case types.WorkflowStatusResolved:
		return "closed", 4
	default:
		return "unknown", 0
	}
}

func mapSecurityHubResources(finding types.AwsSecurityFinding) []ocsf.ResourceDetails {
	var resources []ocsf.ResourceDetails
	for _, resource := range finding.Resources {
		resourceType := *resource.Type
		if resource.Id == nil || *resource.Id == "" {
			continue
		}

		resources = append(resources, ocsf.ResourceDetails{
			Uid:  resource.Id,
			Type: &resourceType,
		})
	}

	return resources
}

func mapSecurityHubCVE(finding types.AwsSecurityFinding) *ocsf.CVE {
	if len(finding.Vulnerabilities) > 0 {
		for _, vuln := range finding.Vulnerabilities {
			if vuln.Id != nil && vuln.Cvss != nil && len(vuln.Cvss) > 0 {
				var cvss []ocsf.CVSSScore
				for _, c := range vuln.Cvss {
					if c.BaseScore != nil && c.Version != nil {
						// The field is VectorString, not Vector
						cvss = append(cvss, ocsf.CVSSScore{
							BaseScore:    *c.BaseScore,
							VectorString: c.BaseVector,
							Version:      *c.Version,
						})
					}
				}

				var references []string
				if vuln.ReferenceUrls != nil {
					references = vuln.ReferenceUrls
				}

				return &ocsf.CVE{
					Uid:        *vuln.Id,
					References: references,
					Cvss:       cvss,
				}
			}
		}
	}
	return nil
}

func mapSecurityHubCWE(finding types.AwsSecurityFinding) *ocsf.CWE {
	if finding.Types != nil {
		for _, t := range finding.Types {
			// t is already a string, not a pointer
			if len(t) > 4 && t[:4] == "CWE-" {
				url := "https://cwe.mitre.org/data/definitions/" + t[4:] + ".html"
				return &ocsf.CWE{
					Uid:    t,
					SrcUrl: &url,
				}
			}
		}
	}
	return nil
}
