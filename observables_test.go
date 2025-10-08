package main

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/telophasehq/go-ocsf/ocsf/v1_5_0"
)

type validatesObservable interface {
	ValidateObservables() error
}

func TestValidateObservables(t *testing.T) {
	var tests = []struct {
		name string
		in   any
		err  error
	}{
		{
			name: "Test that we dont error when there's no observable",
			in:   &v1_5_0.VulnerabilityFinding{},
			err:  nil,
		},
		{
			name: "Test that we error when the observable is non-null but not in observables array",
			in: &v1_5_0.VulnerabilityFinding{
				Resources: []v1_5_0.ResourceDetails{
					{
						Owner: &v1_5_0.User{
							DisplayName: aws.String("jack"),
						},
					},
				},
			},
			err: fmt.Errorf("non-null observable user(21) not found in observables array"),
		},
		{
			name: "Test that we dont error when observable is present",
			in: &v1_5_0.VulnerabilityFinding{
				Vulnerabilities: []v1_5_0.VulnerabilityDetails{
					{
						AffectedCode: []v1_5_0.AffectedCode{
							{
								File: v1_5_0.File{
									InternalName: aws.String("syslog"),
								},
							},
						},
					},
				},
				Observables: []v1_5_0.Observable{
					{
						Name:   aws.String("file"),
						TypeId: 24,
					},
				},
			},
			err: nil,
		},
		{
			name: "Test that we error on arrays of observables when one is missing",
			in: &v1_5_0.VulnerabilityFinding{
				Vulnerabilities: []v1_5_0.VulnerabilityDetails{
					{
						AffectedCode: []v1_5_0.AffectedCode{
							{
								File: v1_5_0.File{
									InternalName: aws.String("syslog"),
								},
							},
						},
					},
				},
				Resources: []v1_5_0.ResourceDetails{
					{
						Owner: &v1_5_0.User{
							DisplayName: aws.String("jack"),
						},
					},
				},
				Observables: []v1_5_0.Observable{
					{
						Name:   aws.String("file"),
						TypeId: 24,
					},
				},
			},
			err: fmt.Errorf("non-null observable user(21) not found in observables array"),
		},
		{
			name: "Test that we dont error on arrays of observables when they are all present",
			in: &v1_5_0.VulnerabilityFinding{
				Vulnerabilities: []v1_5_0.VulnerabilityDetails{
					{
						AffectedCode: []v1_5_0.AffectedCode{
							{
								File: v1_5_0.File{
									InternalName: aws.String("syslog"),
								},
							},
						},
					},
				},
				Resources: []v1_5_0.ResourceDetails{
					{
						Owner: &v1_5_0.User{
							DisplayName: aws.String("jack"),
						},
					},
				},
				Observables: []v1_5_0.Observable{
					{
						Name:   aws.String("file"),
						TypeId: 24,
					},
					{
						Name:   aws.String("user"),
						TypeId: 21,
					},
				},
			},
			err: nil,
		},
		{
			name: "Test that we handle non-array, non-pointer observables",
			in: &v1_5_0.AccountChange{
				User: v1_5_0.User{
					Name: aws.String("jack"),
				},
				Observables: []v1_5_0.Observable{
					{
						Name:   aws.String("user"),
						TypeId: 21,
					},
				},
			},
			err: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.(validatesObservable).ValidateObservables()
			if tt.err == nil && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.err != nil && (err == nil || err.Error() != tt.err.Error()) {
				t.Errorf("got %v, want %v", err, tt.err)
			}
		})
	}

}
