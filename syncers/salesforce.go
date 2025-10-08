package syncers

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/telophasehq/go-ocsf/clients/salesforce"
	"github.com/telophasehq/go-ocsf/datastore"
	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_4_0"
)

type LogFileRecord struct {
	Id          string
	LogFile     string
	ApiVersion  string
	LogDate     string
	CreatedDate string
}

// SalesforceSyncer implements the BaseConnector interface for SalesForce Event Log
type SalesforceSyncer struct {
	client    *salesforce.Client
	Operation string
	pointer   string
	datastore datastore.Datastore[ocsf.APIActivity]
}

// NewConnector creates a new SalesForce Event Log connector
func NewConnector(identity, key, token string) *SalesforceSyncer {
	return &SalesforceSyncer{
		client: salesforce.New(identity, key, token),
	}
}

// Sync gathers EventLogs from the SalesForce Cloud API
func (c *SalesforceSyncer) Sync() error {
	// Authenticate with Salesforce
	err := c.client.Authenticate()
	if err != nil {
		return fmt.Errorf("failed to authenticate with Salesforce: %w", err)
	}

	// If no pointer is stored, set the pointer to a week ago
	now := time.Now().UTC()
	var pointer string

	storedPointer, err := c.GetPointer()
	if err != nil {
		if errors.Is(err, salesforce.ErrNotFound) {
			// Set the pointer to a week ago.
			pointer = now.Add(-7 * 24 * time.Hour).Format(salesforce.SFTimestampFormat)
			c.SetPointer(pointer)
		} else {
			return err
		}
	} else {
		pointer = storedPointer
	}

	// Parse pointer into a time.Time object
	pointerTime, err := time.Parse(salesforce.SFTimestampFormat, pointer)
	if err != nil {
		return fmt.Errorf("invalid pointer timestamp format: %v", err)
	}

	// Validate operation
	validOperation := false
	for _, op := range salesforce.SFOperations {
		if c.Operation == op {
			validOperation = true
			break
		}
	}

	if !validOperation {
		return fmt.Errorf("operation must be one of %v, got '%s'", salesforce.SFOperations, c.Operation)
	}

	// Fetch log files
	logFiles := make(map[string][]LogFileRecord)
	nextRecordsURL := ""

	for {
		var records map[string]interface{}
		var err error

		if nextRecordsURL != "" {
			records, err = c.client.QueryMore(nextRecordsURL)
		} else {
			pointerDate := pointerTime.Format("2006-01-02T00:00:00.00Z")
			query := fmt.Sprintf(salesforce.SOQLEventLogFile, c.Operation, pointerDate)
			records, err = c.client.QueryAll(query)
		}

		if err != nil {
			return err
		}

		// Process records
		recordsList, ok := records["records"].([]interface{})
		if !ok {
			// No records found or invalid response
			break
		}

		for _, rec := range recordsList {
			record, ok := rec.(map[string]interface{})
			if !ok {
				continue
			}

			recordType := record["EventType"].(string)
			if _, exists := logFiles[recordType]; !exists {
				logFiles[recordType] = []LogFileRecord{}
			}

			logFiles[c.Operation] = append(logFiles[c.Operation], LogFileRecord{
				Id:          record["Id"].(string),
				LogFile:     record["LogFile"].(string),
				ApiVersion:  record["ApiVersion"].(string),
				LogDate:     record["LogDate"].(string),
				CreatedDate: record["CreatedDate"].(string),
			})
		}

		nextURL, ok := records["nextRecordsUrl"].(string)
		if !ok || nextURL == "" {
			break
		}
		nextRecordsURL = nextURL
	}

	// Process log files
	for logType := range logFiles {
		for _, logFile := range logFiles[logType] {
			// Fetch log file content
			url := fmt.Sprintf("https://%s/%s", c.client.Instance, logFile.LogFile)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return fmt.Errorf("unable to create request for event log: %v", err)
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.client.SessionID))

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("unable to retrieve event log from SalesForce: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("unable to read event log response: %v", err)
			}

			reader := csv.NewReader(strings.NewReader(string(body)))
			records, err := reader.ReadAll()
			if err != nil {
				return fmt.Errorf("unable to parse CSV from event log: %v", err)
			}

			if len(records) < 2 {
				continue
			}

			headers := records[0]
			var entries []map[string]string

			for _, record := range records[1:] {
				if len(record) != len(headers) {
					continue
				}

				entry := make(map[string]string)
				for i, header := range headers {
					entry[header] = record[i]
				}

				// Skip if the entry is BEFORE the known pointer
				entryTime, err := time.Parse(salesforce.SFTimestampFormat, entry["TIMESTAMP_DERIVED"])
				if err != nil {
					continue
				}

				if entryTime.Unix() <= pointerTime.Unix() {
					continue
				}

				entries = append(entries, entry)
			}

			if len(entries) > 0 {
				c.Save(entries)
			}
		}
	}

	return nil
}

// ToOCSF converts a Salesforce event log entry into an OCSF API activity.
func (c *SalesforceSyncer) ToOCSF(entry map[string]string) (ocsf.APIActivity, error) {
	// Define OCSF class and category constants
	classUID := 6003
	categoryUID := 6
	categoryName := "Application Activity"
	className := "API Activity"

	// Extract method/operation name from entry
	methodName := entry["OPERATION"]
	if methodName == "" {
		methodName = entry["METHOD_NAME"]
	}
	if methodName == "" {
		methodName = "Unknown"
	}

	// Map operation to OCSF activity type
	var activityID int
	var activityName string
	var typeUID int
	var typeName string

	// Check for common method name patterns
	if strings.Contains(strings.ToLower(methodName), "create") ||
		strings.Contains(strings.ToLower(methodName), "insert") {
		activityID = 1
		activityName = "Create"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Create"
	} else if strings.Contains(strings.ToLower(methodName), "get") ||
		strings.Contains(strings.ToLower(methodName), "list") ||
		strings.Contains(strings.ToLower(methodName), "view") ||
		strings.Contains(strings.ToLower(methodName), "select") {
		activityID = 2
		activityName = "Read"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Read"
	} else if strings.Contains(strings.ToLower(methodName), "update") ||
		strings.Contains(strings.ToLower(methodName), "modify") {
		activityID = 3
		activityName = "Update"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Update"
	} else if strings.Contains(strings.ToLower(methodName), "delete") {
		activityID = 4
		activityName = "Delete"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Delete"
	} else {
		activityID = 0
		activityName = "Unknown"
		typeUID = classUID*100 + activityID
		typeName = "API Activity: Unknown"
	}

	// Determine status and severity
	status := "Success"
	statusID := 1
	if entry["STATUS"] == "Failure" || entry["STATUS_CODE"] == "Failure" {
		status = "Failure"
		statusID = 2
	}

	// Default severity to Informational
	severity := "Informational"
	severityID := 1

	// Parse timestamp
	var ts time.Time
	var err error
	timeStr := entry["TIMESTAMP_DERIVED"]
	if timeStr == "" {
		timeStr = entry["CREATED_DATE"]
	}
	if timeStr != "" {
		ts, err = time.Parse(salesforce.SFTimestampFormat, timeStr)
		if err != nil {
			return ocsf.APIActivity{}, fmt.Errorf("failed to parse timestamp: %w", err)
		}
	} else {
		ts = time.Now()
	}

	// Create actor
	var actor ocsf.Actor
	if entry["USER_ID"] != "" || entry["USERNAME"] != "" {
		userID := entry["USER_ID"]
		if userID == "" {
			userID = entry["USERNAME"]
		}
		actor = ocsf.Actor{
			User: &ocsf.User{
				Account: &ocsf.Account{
					TypeId: int32Ptr(12), // Salesforce account
					Type:   stringPtr("Salesforce Account"),
					Uid:    stringPtr(userID),
				},
				Name: stringPtr(entry["USERNAME"]),
				Uid:  stringPtr(userID),
			},
		}
	} else {
		// If no user info, use service name as app name
		actor = ocsf.Actor{
			AppName: stringPtr("Salesforce"),
		}
	}

	// Create API info
	api := ocsf.API{
		Operation: methodName,
		Service: &ocsf.Service{
			Name: stringPtr("Salesforce"),
		},
	}

	// Create source endpoint
	var srcEndpoint ocsf.NetworkEndpoint
	if entry["CLIENT_IP"] != "" {
		srcEndpoint = ocsf.NetworkEndpoint{
			Ip: stringPtr(entry["CLIENT_IP"]),
		}
	} else {
		srcEndpoint = ocsf.NetworkEndpoint{
			SvcName: stringPtr("Salesforce"),
		}
	}

	// Create resources
	var resources []ocsf.ResourceDetails
	if entry["RESOURCE_NAME"] != "" || entry["URI"] != "" {
		resourceName := entry["RESOURCE_NAME"]
		if resourceName == "" {
			resourceName = entry["URI"]
		}
		resources = append(resources, ocsf.ResourceDetails{
			Name: stringPtr(resourceName),
			Type: stringPtr(entry["EVENT_TYPE"]),
		})
	}

	// Create the API Activity
	activity := ocsf.APIActivity{
		ActivityId:   int32(activityID),
		ActivityName: &activityName,
		Actor:        actor,
		Api:          api,
		CategoryName: &categoryName,
		CategoryUid:  int32(categoryUID),
		ClassName:    &className,
		ClassUid:     int32(classUID),
		Status:       &status,
		StatusId:     int32Ptr(int32(statusID)),

		Resources:  resources,
		Severity:   &severity,
		SeverityId: int32(severityID),

		Metadata: ocsf.Metadata{
			CorrelationUid: stringPtr(entry["REQUEST_ID"]),
		},

		SrcEndpoint:    srcEndpoint,
		Time:           ts.UnixMilli(),
		TypeName:       &typeName,
		TypeUid:        int64(typeUID),
		TimezoneOffset: int32Ptr(0),
	}

	return activity, nil
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func int32Ptr(i int32) *int32 {
	return &i
}

// Save stores the collected entries
func (c *SalesforceSyncer) Save(entries []map[string]string) error {
	var activities []ocsf.APIActivity

	for _, entry := range entries {
		activity, err := c.ToOCSF(entry)
		if err != nil {
			// Log error but continue processing other entries
			fmt.Printf("Error converting entry to OCSF: %v\n", err)
			continue
		}
		activities = append(activities, activity)
	}

	// Save activities to datastore
	if len(activities) > 0 {
		if err := c.datastore.Save(context.Background(), activities); err != nil {
			return fmt.Errorf("failed to save API activities: %w", err)
		}
	}

	// Update pointer to the latest timestamp if entries exist
	if len(entries) > 0 {
		latestEntry := entries[len(entries)-1]
		c.SetPointer(latestEntry["TIMESTAMP_DERIVED"])
	}

	return nil
}

// GetPointer returns the current pointer
func (c *SalesforceSyncer) GetPointer() (string, error) {
	if c.pointer == "" {
		return "", fmt.Errorf("pointer not found")
	}
	return c.pointer, nil
}

// SetPointer sets the current pointer
func (c *SalesforceSyncer) SetPointer(pointer string) {
	c.pointer = pointer
}

// WithOperation sets the operation for the connector
func (c *SalesforceSyncer) WithOperation(operation string) *SalesforceSyncer {
	c.Operation = operation
	return c
}
