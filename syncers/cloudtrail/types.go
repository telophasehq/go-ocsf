package cloudtrail

import (
	"encoding/json"
	"time"

	ocsf "github.com/telophasehq/go-ocsf/ocsf/v1_4_0"
)

type batch struct{ evts []ocsf.APIActivity }

// LogFile is the top-level wrapper for each gzipped file.
type LogFile struct {
	Records []CloudtrailEvent `json:"Records"`
}

// TrailEvent mirrors one element of the Records array.
//
// Only the most common fields are typed strongly; everything else is
// left as json.RawMessage so you don’t have to chase dozens of service-
// specific schemas.  Add more typed fields later if you need them.
type CloudtrailEvent struct {
	// ---- required-ish core fields ---------------------------------
	EventVersion string    `json:"eventVersion"`
	EventID      string    `json:"eventID"`
	EventTime    time.Time `json:"eventTime"`
	EventSource  string    `json:"eventSource"`
	EventName    string    `json:"eventName"`
	AwsRegion    string    `json:"awsRegion"`
	EventType    string    `json:"eventType"` // e.g. AwsApiCall, AwsServiceEvent
	SourceIP     string    `json:"sourceIPAddress"`
	UserAgent    string    `json:"userAgent"`

	// ---- identity --------------------------------------------------
	UserIdentity UserIdentity `json:"userIdentity"`

	// ---- outcome ---------------------------------------------------
	ErrorCode    *string `json:"errorCode,omitempty"`
	ErrorMessage *string `json:"errorMessage,omitempty"`

	// ---- request / response payloads -------------------------------
	RequestParameters   json.RawMessage `json:"requestParameters,omitempty"`
	ResponseElements    json.RawMessage `json:"responseElements,omitempty"`
	AdditionalEventData json.RawMessage `json:"additionalEventData,omitempty"`

	// ---- resources array (data events, some control-plane calls) ---
	Resources []ResourceRef `json:"resources,omitempty"`

	// ---- misc ------------------------------------------------------
	ReadOnly            *bool           `json:"readOnly,omitempty"`
	ManagementEvent     *bool           `json:"managementEvent,omitempty"`
	RecipientAccountID  string          `json:"recipientAccountId"`
	SharedEventID       *string         `json:"sharedEventID,omitempty"`
	ServiceEventDetails json.RawMessage `json:"serviceEventDetails,omitempty"`
	TlsDetails          json.RawMessage `json:"tlsDetails,omitempty"`
	VpcEndpointID       *string         `json:"vpcEndpointId,omitempty"`
}

// ---- nested structs ----------------------------------------------

type UserIdentity struct {
	Type        string  `json:"type"` // Root, IAMUser, AssumedRole, …
	PrincipalID string  `json:"principalId"`
	Arn         string  `json:"arn"`
	AccountID   *string `json:"accountId,omitempty"`
	AccessKeyID string  `json:"accessKeyId,omitempty"`

	UserName *string `json:"userName,omitempty"` // present for IAMUser

	InvokedBy *string `json:"invokedBy,omitempty"` // e.g. „AWS Internal“

	SessionContext *SessionContext `json:"sessionContext,omitempty"`
}

type SessionContext struct {
	Attributes struct {
		MfaAuthenticated string    `json:"mfaAuthenticated"`
		CreationDate     time.Time `json:"creationDate"`
	} `json:"attributes"`

	// present when the session was assumed via STS
	SessionIssuer *SessionIssuer `json:"sessionIssuer,omitempty"`
}

type SessionIssuer struct {
	Type        string `json:"type"`
	PrincipalID string `json:"principalId"`
	Arn         string `json:"arn"`
	AccountID   string `json:"accountId"`
	UserName    string `json:"userName"`
}

type ResourceRef struct {
	ARN       string  `json:"ARN"`
	AccountID *string `json:"accountId,omitempty"`
	Type      string  `json:"type,omitempty"` // e.g. "AWS::S3::Object"
}
