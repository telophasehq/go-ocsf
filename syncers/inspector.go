package syncers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/samsarahq/go/oops"
	"github.com/telophasehq/go-ocsf/datastore"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_4_0"
)

type InspectorOCSFSyncer struct {
	inspectorClient *inspector2.Client
	datastore       datastore.Datastore[ocsf.VulnerabilityFinding]
}

// NewInspectorOCSFSyncer creates a new InspectorOCSFSyncer
// It initializes the Inspector client and datastore.
func NewInspectorOCSFSyncer(ctx context.Context, inspectorClient *inspector2.Client, storageOpts datastore.StorageOpts) (DataSync, error) {
	dataStoreInst, err := datastore.SetupStorage[ocsf.VulnerabilityFinding](ctx, storageOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to setup datastore: %w", err)
	}

	return &InspectorOCSFSyncer{
		inspectorClient: inspectorClient,
		datastore:       dataStoreInst,
	}, nil
}

// Sync synchronizes Inspector data with the OCSF datastore
// It fetches all findings from Inspector, builds OCSF findings, and saves them to the datastore.
func (s *InspectorOCSFSyncer) Sync(ctx context.Context) error {
	slog.Info("syncing Inspector data")

	var nextToken *string
	for {
		inspectorFindingsOutput, err := s.inspectorClient.ListFindings(
			ctx,
			&inspector2.ListFindingsInput{
				MaxResults: aws.Int32(100),
				SortCriteria: &types.SortCriteria{
					Field:     types.SortFieldLastObservedAt,
					SortOrder: types.SortOrderDesc,
				},
				NextToken: nextToken,
			},
		)
		if err != nil {
			return oops.Wrapf(err, "failed to list all findings")
		}

		slog.Info("Inspector findings", "num_findings", len(inspectorFindingsOutput.Findings))

		var findingsToSave []ocsf.VulnerabilityFinding

		for _, inspectorFinding := range inspectorFindingsOutput.Findings {
			finding, err := s.ToOCSF(ctx, inspectorFinding)
			if err != nil {
				return oops.Wrapf(err, "failed to build OCSF finding")
			}

			findingsToSave = append(findingsToSave, finding)
		}

		err = s.datastore.Save(ctx, findingsToSave)
		if err != nil {
			return oops.Wrapf(err, "failed to save findings")
		}

		if inspectorFindingsOutput.NextToken == nil {
			break
		}

		nextToken = inspectorFindingsOutput.NextToken
	}

	slog.Info("Finished Inspector sync")
	return nil
}

// ToOCSF converts a Inspector finding into an OCSF vulnerability finding.
func (s *InspectorOCSFSyncer) ToOCSF(ctx context.Context, inspectorFinding types.Finding) (ocsf.VulnerabilityFinding, error) {
	severity, severityID := mapInspectorSeverity(inspectorFinding.Severity)
	status, statusID := mapInspectorStatus(inspectorFinding.Status)
	createdAt := inspectorFinding.FirstObservedAt
	var endTime *time.Time

	if status == string(types.FindingStatusClosed) {
		endTime = inspectorFinding.UpdatedAt
	}

	lastSeenTime := inspectorFinding.LastObservedAt
	modifiedTime := inspectorFinding.UpdatedAt
	firstSeenTime := inspectorFinding.FirstObservedAt
	vendorName := "AWS"
	var exploitAvailable bool
	if inspectorFinding.ExploitAvailable == types.ExploitAvailableYes {
		exploitAvailable = true
	} else {
		exploitAvailable = false
	}

	var fixAvailable bool
	if inspectorFinding.FixAvailable == types.FixAvailableYes {
		fixAvailable = true
	} else {
		fixAvailable = false
	}

	var remediation *ocsf.Remediation
	if inspectorFinding.Remediation != nil {
		var description string
		if inspectorFinding.Remediation.Recommendation != nil && inspectorFinding.Remediation.Recommendation.Text != nil {
			description = *inspectorFinding.Remediation.Recommendation.Text
		}

		var references []string
		if inspectorFinding.Remediation.Recommendation != nil && inspectorFinding.Remediation.Recommendation.Url != nil {
			references = append(references, *inspectorFinding.Remediation.Recommendation.Url)
		}

		remediation = &ocsf.Remediation{
			Desc:       description,
			References: references,
		}
	}

	var title string
	if inspectorFinding.Title != nil {
		title = *inspectorFinding.Title
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
			Cwe:                mapInspectorCWE(inspectorFinding),
			Cve:                mapInspectorCVE(inspectorFinding),
			Desc:               inspectorFinding.Description,
			Title:              &title,
			Severity:           &severity,
			IsExploitAvailable: &exploitAvailable,
			FirstSeenTime:      createdTimeInt,
			IsFixAvailable:     &fixAvailable,
			LastSeenTime:       lastSeenTimeInt,
			VendorName:         &vendorName,
			AffectedCode:       mapInspectorAffectedCode(inspectorFinding),
			AffectedPackages:   mapInspectorAffectedPackages(inspectorFinding),
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

	if inspectorFinding.UpdatedAt == nil || inspectorFinding.UpdatedAt == inspectorFinding.FirstObservedAt {
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
		if inspectorFinding.UpdatedAt != nil {
			eventTime = *inspectorFinding.UpdatedAt
		} else {
			eventTime = *inspectorFinding.LastObservedAt
		}
	}

	productName := "Inspector"

	metadata := ocsf.Metadata{
		Product: ocsf.Product{
			Name:       &productName,
			VendorName: &vendorName,
		},
		Version: "1.4.0",
	}

	firstSeenTimeInt := firstSeenTime.UnixMilli()
	modifiedTimeInt := modifiedTime.UnixMilli()
	endTimeInt := endTime.UnixMilli()
	eventTimeInt := eventTime.UnixMilli()

	findingInfo := ocsf.FindingInformation{
		Uid:           *inspectorFinding.FindingArn,
		Title:         &title,
		Desc:          inspectorFinding.Description,
		CreatedTime:   createdTimeInt,
		FirstSeenTime: firstSeenTimeInt,
		LastSeenTime:  lastSeenTimeInt,
		ModifiedTime:  modifiedTimeInt,
		DataSources:   []string{"inspector"},
		Types:         []string{"Vulnerability"},
	}

	finding := ocsf.VulnerabilityFinding{
		Time:            eventTimeInt,
		StartTime:       firstSeenTimeInt,
		EndTime:         endTimeInt,
		ActivityId:      activityID,
		ActivityName:    &activityName,
		CategoryUid:     categoryUID,
		CategoryName:    &categoryName,
		ClassUid:        classUID,
		ClassName:       &className,
		Message:         inspectorFinding.Description,
		Metadata:        metadata,
		Resources:       mapInspectorResources(inspectorFinding),
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

func regionFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	return parts[3]
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

func mapInspectorSeverity(severity types.Severity) (string, int) {
	switch severity {
	case types.SeverityInformational:
		return "informational", 1
	case types.SeverityLow:
		return "low", 2
	case types.SeverityMedium:
		return "medium", 3
	case types.SeverityHigh:
		return "high", 4
	case types.SeverityCritical:
		return "critical", 5
	default:
		return "unknown", 0
	}
}

func mapInspectorStatus(status types.FindingStatus) (string, int32) {
	switch status {
	case types.FindingStatusActive:
		return "open", 1
	case types.FindingStatusSuppressed:
		return "suppressed", 3
	case types.FindingStatusClosed:
		return "closed", 4
	default:
		return "unknown", 0
	}
}

func mapInspectorResources(finding types.Finding) []ocsf.ResourceDetails {
	var resources []ocsf.ResourceDetails
	for _, resource := range finding.Resources {

		resourceType := string(resource.Type)
		resources = append(resources, ocsf.ResourceDetails{
			Uid:  resource.Id,
			Type: &resourceType,
		})
	}

	return resources
}

func mapInspectorCVE(finding types.Finding) *ocsf.CVE {
	if finding.PackageVulnerabilityDetails != nil && finding.PackageVulnerabilityDetails.VulnerabilityId != nil {
		var cvss []ocsf.CVSSScore
		for _, c := range finding.PackageVulnerabilityDetails.Cvss {
			cvss = append(cvss, ocsf.CVSSScore{
				BaseScore:    *c.BaseScore,
				VectorString: c.ScoringVector,
				Version:      *c.Version,
			})
		}

		return &ocsf.CVE{
			Uid:        *finding.PackageVulnerabilityDetails.VulnerabilityId,
			References: finding.PackageVulnerabilityDetails.ReferenceUrls,
			Cvss:       cvss,
		}
	}
	return nil
}

func mapInspectorCWE(finding types.Finding) *ocsf.CWE {
	if finding.CodeVulnerabilityDetails != nil && finding.CodeVulnerabilityDetails.Cwes != nil {
		for _, cwe := range finding.CodeVulnerabilityDetails.Cwes {

			url := fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(cwe, "CWE-"))
			return &ocsf.CWE{
				Uid:    cwe,
				SrcUrl: &url,
			}
		}
	}
	return nil
}

func mapInspectorAffectedCode(finding types.Finding) []ocsf.AffectedCode {
	var affectedCode []ocsf.AffectedCode

	if finding.CodeVulnerabilityDetails != nil {
		startLine := int32(0)
		endLine := int32(0)
		var filePath string

		if finding.CodeVulnerabilityDetails.FilePath != nil {
			if finding.CodeVulnerabilityDetails.FilePath.StartLine != nil {
				startLine = *finding.CodeVulnerabilityDetails.FilePath.StartLine
			}
			if finding.CodeVulnerabilityDetails.FilePath.EndLine != nil {
				endLine = *finding.CodeVulnerabilityDetails.FilePath.EndLine
			}

			if finding.CodeVulnerabilityDetails.FilePath.FilePath != nil {
				filePath = *finding.CodeVulnerabilityDetails.FilePath.FilePath
			}
		}

		affectedCode = append(affectedCode, ocsf.AffectedCode{
			File: ocsf.File{
				Path: &filePath,
			},
			StartLine: &startLine,
			EndLine:   &endLine,
		})
	}

	return affectedCode
}

func mapInspectorAffectedPackages(finding types.Finding) []ocsf.AffectedSoftwarePackage {
	var affectedPackages []ocsf.AffectedSoftwarePackage

	if finding.PackageVulnerabilityDetails != nil {
		pkg := finding.PackageVulnerabilityDetails.VulnerablePackages
		for _, p := range pkg {

			packageManager := string(p.PackageManager)
			epoch := p.Epoch

			var remediation *ocsf.Remediation
			if p.Remediation != nil {
				var remediationDescription string
				if p.Remediation != nil {
					remediationDescription = *p.Remediation
				}
				remediation = &ocsf.Remediation{
					Desc: remediationDescription,
				}
			}

			affectedPackages = append(affectedPackages, ocsf.AffectedSoftwarePackage{
				Name:           *p.Name,
				Version:        *p.Version,
				Architecture:   p.Arch,
				PackageManager: &packageManager,
				Release:        p.Release,
				Path:           p.FilePath,
				FixedInVersion: p.FixedInVersion,
				Epoch:          &epoch,
				Remediation:    remediation,
			})
		}
	}

	return affectedPackages
}
