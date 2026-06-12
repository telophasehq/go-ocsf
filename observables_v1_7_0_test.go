package main

import (
	"fmt"
	"testing"

	"github.com/telophasehq/go-ocsf/ocsf/v1_7_0"
)

type validatesObservableV170 interface {
	ValidateObservables() error
}

func strPtr(v string) *string {
	return &v
}

func TestValidateObservablesV170(t *testing.T) {
	tests := []struct {
		name string
		in   validatesObservableV170
		err  error
	}{
		{
			name: "vulnerability finding with no observable fields set",
			in:   &v1_7_0.VulnerabilityFinding{},
			err:  nil,
		},
		{
			name: "vulnerability finding missing user observable in list",
			in: &v1_7_0.VulnerabilityFinding{
				Resources: []v1_7_0.ResourceDetails{
					{Owner: &v1_7_0.User{Name: strPtr("jack")}},
				},
			},
			err: fmt.Errorf("non-null observable user(21) not found in observables array"),
		},
		{
			name: "vulnerability finding includes user observable in list",
			in: &v1_7_0.VulnerabilityFinding{
				Resources: []v1_7_0.ResourceDetails{
					{Owner: &v1_7_0.User{Name: strPtr("jack")}},
				},
				Observables: []v1_7_0.Observable{
					{Name: strPtr("user"), TypeId: 21},
				},
			},
			err: nil,
		},
		{
			name: "account change validates required user observable",
			in: &v1_7_0.AccountChange{
				User: v1_7_0.User{Name: strPtr("jane")},
				Observables: []v1_7_0.Observable{
					{Name: strPtr("user"), TypeId: 21},
				},
			},
			err: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.ValidateObservables()
			if tt.err == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.err != nil {
				if err == nil {
					t.Fatalf("got nil error, want %v", tt.err)
				}
				if err.Error() != tt.err.Error() {
					t.Fatalf("got %v, want %v", err, tt.err)
				}
			}
		})
	}
}
