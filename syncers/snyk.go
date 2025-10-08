package syncers

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/samsarahq/go/oops"
	"github.com/telophasehq/go-ocsf/clients/snyk"
	"github.com/telophasehq/go-ocsf/datastore"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_4_0"
)

type DataSync interface {
	Sync(ctx context.Context) error
}

type SnykOCSFSyncer struct {
	snykClient *snyk.Client
	datastore  datastore.Datastore[ocsf.VulnerabilityFinding]
	org        *snyk.Org
}

// NewSnykOCSFSyncer creates a new SnykOCSFSyncer
// It initializes the Snyk client and datastore, and fetches the organization details.
func NewSnykOCSFSyncer(ctx context.Context, snykClient *snyk.Client, storageOpts datastore.StorageOpts) (DataSync, error) {
	dataStoreInst, err := datastore.SetupStorage[ocsf.VulnerabilityFinding](ctx, storageOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to setup datastore: %w", err)
	}

	org, err := snykClient.GetOrg(ctx)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to fetch org")
	}

	return &SnykOCSFSyncer{
		snykClient: snykClient,
		datastore:  dataStoreInst,
		org:        org,
	}, nil
}

// Sync synchronizes Snyk data with the OCSF datastore
// It fetches all issues from Snyk, builds OCSF findings, and saves them to the datastore.
func (s *SnykOCSFSyncer) Sync(ctx context.Context) error {
	slog.Info("syncing Snyk data")

	issues, err := s.snykClient.ListIssues(ctx)
	if err != nil {
		return oops.Wrapf(err, "failed to list all issues")
	}

	slog.Info("found Snyk issues", "num_issues", len(issues))

	var findingIDs []string
	for _, issue := range issues {
		findingIDs = append(findingIDs, issue.ID)
	}

	var findingsToSave []ocsf.VulnerabilityFinding
	for _, issue := range issues {
		project, err := s.snykClient.GetProject(ctx, issue.Relationships.ScanItem.Data.ID)
		if err != nil {
			return oops.Wrapf(err, "failed to fetch project for Snyk issue")
		}

		finding, err := s.ToOCSF(ctx, issue, project)
		if err != nil {
			return oops.Wrapf(err, "failed to build OCSF finding")
		}

		findingsToSave = append(findingsToSave, finding)
	}

	err = s.datastore.Save(ctx, findingsToSave)
	if err != nil {
		return oops.Wrapf(err, "failed to save findings")
	}

	slog.Info("Finished Snyk sync")
	return nil
}

// ToOCSF converts a Snyk issue into an OCSF vulnerability finding.
func (s *SnykOCSFSyncer) ToOCSF(ctx context.Context, issue snyk.Issue, project *snyk.Project) (ocsf.VulnerabilityFinding, error) {
	severity, severityID := mapSnykSeverity(issue.Attributes.EffectiveSeverityLevel)
	status, statusID := mapSnykStatus(issue.Attributes.Status)
	createdAt := issue.Attributes.CreatedAt
	updatedAt := issue.Attributes.UpdatedAt
	var endTime *time.Time
	if status == "Closed" {
		endTime = &updatedAt
	}

	var lastSeenTime *time.Time
	if status == "Open" {
		lastSeenTime = &updatedAt
	} else {
		// This technically isn't correct because its when the issue was closed,
		// but we don't have a way to know when the issue was last seen.
		lastSeenTime = &updatedAt
	}

	projectName := project.Attributes.Name
	vendorName := "Snyk"

	var vulnerabilities []ocsf.VulnerabilityDetails
	exploitAvailable := issue.Attributes.ExploitDetails != nil

	var fixAvailable bool
	var remediation *ocsf.Remediation
	for _, coordinate := range issue.Attributes.Coordinates {
		fixAvailable = fixAvailable || coordinate.IsFixableManually || coordinate.IsFixableSnyk ||
			coordinate.IsFixableUpstream || coordinate.IsPatchable || coordinate.IsPinnable || coordinate.IsUpgradeable

		for _, remedy := range coordinate.Remedies {
			if remediation == nil {
				remediation = &ocsf.Remediation{
					Desc: remedy.Description,
				}
			} else {
				// Snyk may have multiple remediations for a single issue.
				remediation.Desc = fmt.Sprintf("%s\n\nor\n\n%s", remediation.Desc, remedy.Description)
			}
		}
	}

	issueURL := fmt.Sprintf("https://app.snyk.io/org/%s/project/%s#issue-%s", s.org.Attributes.Slug, project.ID, issue.Attributes.Key)
	cwe := snykIssueCWE(issue)

	createdTimeInt := createdAt.UnixMilli()

	var lastSeenTimeInt int64
	if lastSeenTime != nil {
		lastSeenTimeInt = lastSeenTime.UnixMilli()
	}

	if len(issue.Attributes.Problems) == 0 {
		vulnerabilities = append(vulnerabilities, ocsf.VulnerabilityDetails{
			Cwe:                cwe,
			Desc:               &issue.Attributes.Description,
			Title:              &issue.Attributes.Title,
			Severity:           &severity,
			IsExploitAvailable: &exploitAvailable,
			FirstSeenTime:      createdTimeInt,
			IsFixAvailable:     &fixAvailable,
			LastSeenTime:       lastSeenTimeInt,
			VendorName:         &vendorName,
			AffectedCode:       snykAffectedCode(issue, project),
			AffectedPackages:   snykAffectedPackages(issue),
			Remediation:        remediation,
			References:         []string{issueURL},
		})
	} else {
		for _, problem := range issue.Attributes.Problems {
			reference := issueURL
			if problem.URL != nil {
				reference = *problem.URL
			}

			vulnerabilities = append(vulnerabilities, ocsf.VulnerabilityDetails{
				Cve:                snykProblemToCVE(problem),
				Cwe:                cwe,
				AffectedCode:       snykAffectedCode(issue, project),
				AffectedPackages:   snykAffectedPackages(issue),
				Desc:               &issue.Attributes.Description,
				Title:              &issue.Attributes.Title,
				Severity:           &severity,
				IsExploitAvailable: &exploitAvailable,
				FirstSeenTime:      createdTimeInt,
				IsFixAvailable:     &fixAvailable,
				LastSeenTime:       lastSeenTimeInt,
				VendorName:         &vendorName,
				Remediation:        remediation,
				References:         []string{reference},
			})
		}
	}

	resourceType := project.Attributes.Type
	resource := ocsf.ResourceDetails{
		Uid:  &issue.ID,
		Name: &projectName,
		Type: &resourceType,
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

	if createdAt.Equal(updatedAt) {
		activityID = int32(1)
		activityName = "Create"
		typeUID = int64(classUID)*100 + int64(activityID)
		typeName = "Vulnerability Finding: Create"
		eventTime = createdAt
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
		eventTime = *lastSeenTime
	}

	productName := "Snyk"

	metadata := ocsf.Metadata{
		Product: ocsf.Product{
			Name:       &productName,
			VendorName: &vendorName,
		},
		Version: "1.4.0",
	}

	var modifiedTimeInt int64
	if !updatedAt.Equal(createdAt) {
		modifiedTimeInt = updatedAt.UnixMilli()
	}

	var endTimeInt int64
	if endTime != nil {
		endTimeInt = endTime.UnixMilli()
	}

	findingInfo := ocsf.FindingInformation{
		Uid:           issue.ID,
		Title:         &issue.Attributes.Title,
		Desc:          &issue.Attributes.Description,
		CreatedTime:   createdTimeInt,
		FirstSeenTime: createdTimeInt,
		LastSeenTime:  lastSeenTimeInt,
		ModifiedTime:  modifiedTimeInt,
		DataSources:   []string{"snyk"},
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
		Message:         &issue.Attributes.Description,
		Metadata:        metadata,
		Resources:       []ocsf.ResourceDetails{resource},
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

func mapSnykSeverity(snykSeverity string) (string, int) {
	switch snykSeverity {
	case "info":
		return "informational", 1
	case "low":
		return "low", 2
	case "medium":
		return "medium", 3
	case "high":
		return "high", 4
	case "critical":
		return "critical", 5
	default:
		return "unknown", 0
	}
}

func mapSnykStatus(snykStatus string) (string, int32) {
	switch snykStatus {
	case "resolved":
		return "closed", 4
	default:
		return "open", 1
	}
}

func snykProblemToCVE(problem snyk.Problem) *ocsf.CVE {
	if problem.Source == "NVD" {
		var problemURL string
		if problem.URL != nil {
			problemURL = *problem.URL
		}
		return &ocsf.CVE{
			Uid: problem.ID,
			References: []string{
				problemURL,
			},
		}
	}
	return nil
}

func snykIssueCWE(issue snyk.Issue) *ocsf.CWE {
	for _, class := range issue.Attributes.Classes {
		if class.Source == "CWE" {
			return &ocsf.CWE{
				Uid:    class.ID,
				SrcUrl: class.URL,
			}
		}
	}
	return nil
}

func snykAffectedCode(issue snyk.Issue, project *snyk.Project) []ocsf.AffectedCode {
	var affectedCode []ocsf.AffectedCode
	for _, coordinate := range issue.Attributes.Coordinates {
		for _, representation := range coordinate.Representations {
			fileName := project.Attributes.TargetFile
			lineNumber := int32(0)
			endLine := int32(0)

			if representation.SourceLocation == nil {
				continue
			}

			if representation.SourceLocation.Region.Start.Line > 0 {
				lineNumber = int32(representation.SourceLocation.Region.Start.Line)
			}
			if representation.SourceLocation.Region.End.Line > 0 {
				endLine = int32(representation.SourceLocation.Region.End.Line)
			}

			fileObj := ocsf.File{
				Path: &fileName,
			}

			affectedCode = append(affectedCode, ocsf.AffectedCode{
				File:      fileObj,
				StartLine: &lineNumber,
				EndLine:   &endLine,
			})
		}
	}

	return affectedCode
}

func snykAffectedPackages(issue snyk.Issue) []ocsf.AffectedSoftwarePackage {
	var affectedPackage []ocsf.AffectedSoftwarePackage
	for _, coordinate := range issue.Attributes.Coordinates {
		for _, representation := range coordinate.Representations {
			if representation.Dependency == nil {
				continue
			}

			affectedPackage = append(affectedPackage, ocsf.AffectedSoftwarePackage{
				Name:    representation.Dependency.PackageName,
				Version: representation.Dependency.PackageVersion,
			})
		}
	}
	return affectedPackage
}
