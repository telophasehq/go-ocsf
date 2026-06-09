package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFakeCmd(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name+".cmd")
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("failed writing %s: %v", path, err)
	}
}

func resetGeneratorGlobals() {
	refTree = make(map[string]map[string]bool)
	refStructsUsed = make(map[string]bool)
}

func TestSanitizeSchemaHandlesSchemaWithoutRootProfiles(t *testing.T) {
	schema := map[string]interface{}{
		"classes": map[string]interface{}{
			"sample_class": map[string]interface{}{
				"profiles": []interface{}{"profile_only_field"},
				"attributes": map[string]interface{}{
					"profile_only_field": map[string]interface{}{"type": "string_t", "requirement": "optional"},
					"regular_field":      map[string]interface{}{"type": "string_t", "requirement": "optional"},
					"old_field":          map[string]interface{}{"type": "string_t", "requirement": "optional", "@deprecated": true},
					"time_dt":            map[string]interface{}{"type": "string_t", "requirement": "optional"},
				},
			},
		},
		"objects": map[string]interface{}{
			"sample_object": map[string]interface{}{
				"attributes": map[string]interface{}{
					"legacy":   map[string]interface{}{"type": "string_t", "@deprecated": true},
					"stamp_dt": map[string]interface{}{"type": "string_t"},
					"keep":     map[string]interface{}{"type": "string_t"},
				},
			},
		},
		"types": map[string]interface{}{
			"string_t": map[string]interface{}{"caption": "String"},
		},
	}

	classes, objects, types := sanitizeSchema(schema)
	if classes == nil || objects == nil || types == nil {
		t.Fatalf("expected non-nil sanitized maps")
	}

	classAttrs := classes["sample_class"].(map[string]interface{})["attributes"].(map[string]interface{})
	if _, ok := classAttrs["profile_only_field"]; ok {
		t.Fatalf("expected profile-only field to be removed")
	}
	if _, ok := classAttrs["old_field"]; ok {
		t.Fatalf("expected deprecated class field to be removed")
	}
	if _, ok := classAttrs["time_dt"]; ok {
		t.Fatalf("expected _dt class field to be removed")
	}
	if _, ok := classAttrs["regular_field"]; !ok {
		t.Fatalf("expected regular class field to remain")
	}

	objAttrs := objects["sample_object"].(map[string]interface{})["attributes"].(map[string]interface{})
	if _, ok := objAttrs["legacy"]; ok {
		t.Fatalf("expected deprecated object field to be removed")
	}
	if _, ok := objAttrs["stamp_dt"]; ok {
		t.Fatalf("expected _dt object field to be removed")
	}
	if _, ok := objAttrs["keep"]; !ok {
		t.Fatalf("expected regular object field to remain")
	}
}

func TestResolveOCSFTypeResolvesAliases(t *testing.T) {
	types := map[string]interface{}{
		"string_t": map[string]interface{}{"caption": "String"},
		"alias_t":  map[string]interface{}{"type": "string_t"},
	}

	resolved, err := resolveOCSFType("alias_t", types)
	if err != nil {
		t.Fatalf("resolveOCSFType() unexpected error: %v", err)
	}
	if resolved != "string" {
		t.Fatalf("resolveOCSFType() = %q, want %q", resolved, "string")
	}
}

func TestGenerateGoStructObjectTUsesObjectType(t *testing.T) {
	resetGeneratorGlobals()

	tmpDir := t.TempDir()
	class := map[string]interface{}{
		"name":    "sample_class",
		"caption": "Sample Class",
		"attributes": map[string]interface{}{
			"owner": map[string]interface{}{
				"caption":     "Owner",
				"description": "Resource owner",
				"type":        "object_t",
				"object_type": "user",
				"requirement": "optional",
				"is_array":    false,
			},
		},
	}
	objects := map[string]interface{}{
		"user": map[string]interface{}{
			"caption": "User",
		},
	}

	err := generateGoStruct("v1_7_0", tmpDir, class, objects, map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("generateGoStruct() unexpected error: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(tmpDir, "sample_class.go"))
	if err != nil {
		t.Fatalf("failed reading generated file: %v", err)
	}
	generated := string(content)
	if !strings.Contains(generated, "Owner *User") {
		t.Fatalf("generated struct did not contain expected object_t field type")
	}
	if !strings.Contains(generated, "Type: UserStruct") {
		t.Fatalf("generated arrow fields did not contain expected object_t arrow type")
	}
}

func TestFormatGoFileFallsBackToGofmt(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fakebin")
	if err := os.MkdirAll(fakeBin, 0755); err != nil {
		t.Fatalf("failed creating fake bin dir: %v", err)
	}

	goimportsFailScript := "@echo off\r\nexit /b 1\r\n"
	gofmtSuccessScript := "@echo off\r\nif \"%1\"==\"-w\" (\r\n  echo // formatted by fake gofmt>>\"%2\"\r\n  exit /b 0\r\n)\r\nexit /b 1\r\n"
	writeFakeCmd(t, fakeBin, "goimports", goimportsFailScript)
	writeFakeCmd(t, fakeBin, "gofmt", gofmtSuccessScript)

	t.Setenv("PATH", fakeBin+";"+os.Getenv("PATH"))

	target := filepath.Join(tmpDir, "target.go")
	if err := os.WriteFile(target, []byte("package p\n"), 0644); err != nil {
		t.Fatalf("failed creating target file: %v", err)
	}

	if err := formatGoFile(target); err != nil {
		t.Fatalf("formatGoFile() unexpected error: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed reading target file: %v", err)
	}
	if !strings.Contains(string(content), "formatted by fake gofmt") {
		t.Fatalf("expected fallback gofmt formatter to update file")
	}
}

func TestFormatGoFileReturnsErrorWhenBothFormattersFail(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fakebin")
	if err := os.MkdirAll(fakeBin, 0755); err != nil {
		t.Fatalf("failed creating fake bin dir: %v", err)
	}

	failScript := "@echo off\r\nexit /b 1\r\n"
	writeFakeCmd(t, fakeBin, "goimports", failScript)
	writeFakeCmd(t, fakeBin, "gofmt", failScript)

	t.Setenv("PATH", fakeBin+";"+os.Getenv("PATH"))

	target := filepath.Join(tmpDir, "target.go")
	if err := os.WriteFile(target, []byte("package p\n"), 0644); err != nil {
		t.Fatalf("failed creating target file: %v", err)
	}

	err := formatGoFile(target)
	if err == nil {
		t.Fatalf("expected formatGoFile() to fail when both formatters fail")
	}
	if !strings.Contains(err.Error(), "goimports and gofmt both failed") {
		t.Fatalf("unexpected error text: %v", err)
	}
}
