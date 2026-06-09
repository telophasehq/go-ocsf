package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

var (
	refTree        = make(map[string]map[string]bool)
	refStructsUsed = make(map[string]bool)
)

type Observable struct {
	Name   string
	TypeID int
}

type GenerationSpec struct {
	Version string
	Package string
	Dir     string
}

func main() {

	toGenerate := []GenerationSpec{
		{
			Version: "1.4.0",
			Package: "v1_4_0",
			Dir:     "../ocsf/v1_4_0",
		},
		{
			Version: "1.5.0",
			Package: "v1_5_0",
			Dir:     "../ocsf/v1_5_0",
		},
		{
			Version: "1.7.0",
			Package: "v1_7_0",
			Dir:     "../ocsf/v1_7_0",
		},
	}

	for _, genSpec := range toGenerate {
		schema, err := loadSchema(genSpec.Version)
		if err != nil {
			log.Fatalf("Failed to load schema data: %v", err)
		}
		classes, objects, types := sanitizeSchema(schema)

		err = os.MkdirAll(genSpec.Dir, 0755)
		if err != nil {
			log.Fatalf("Failed to create directory: %v", err)
		}

		generateSchema(genSpec.Package, genSpec.Dir, classes, objects, types)
	}
}

func generateSchema(packageName, genDir string, classes, objects, types map[string]interface{}) {
	for _, class := range sortedKeys(classes) {
		visited := make(map[string]bool)
		observables, err := resolveObservables(classes[class].(map[string]interface{}), objects, visited)
		if err != nil {
			log.Fatalf("Failed to generate Go struct: %v", err)
		}

		err = generateGoStruct(
			packageName,
			genDir,
			classes[class].(map[string]interface{}),
			objects,
			types,
			observables,
		)
		if err != nil {
			log.Fatalf("Failed to generate Go struct: %v", err)
		}
	}

	for _, object := range sortedKeys(objects) {
		err := generateGoStruct(
			packageName,
			genDir,
			objects[object].(map[string]interface{}),
			objects,
			types,
			[]Observable{}, // observables should only be generated for classes.
		)
		if err != nil {
			log.Fatalf("Failed to generate Go struct: %v", err)
		}
	}

	for usedRefStruct := range refStructsUsed {
		err := generateRefStructs(genDir, objects[usedRefStruct].(map[string]interface{}))
		if err != nil {
			log.Fatalf("Failed to generate ref struct: %v", err)
		}
	}
}

func loadSchema(version string) (data map[string]interface{}, err error) {
	schemaData, err := os.ReadFile(fmt.Sprintf("%s.json", version))
	if err != nil {
		return nil, fmt.Errorf("failed to read schema data for version %s: %v", version, err)
	}

	err = json.Unmarshal(schemaData, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal schema data for version %s: %v", version, err)
	}

	return data, nil
}

func sanitizeSchema(schema map[string]interface{}) (classes, objects, types map[string]interface{}) {
	var ok bool
	classes, ok = schema["classes"].(map[string]interface{})
	if !ok {
		log.Println("Error: schema does not contain 'classes' key or it has unexpected type")
		return nil, nil, nil
	}

	objects, ok = schema["objects"].(map[string]interface{})
	if !ok {
		log.Println("Error: schema does not contain 'objects' key or it has unexpected type")
		return nil, nil, nil
	}

	types, ok = schema["types"].(map[string]interface{})
	if !ok {
		log.Println("Error: schema does not contain 'types' key or it has unexpected type")
		return nil, nil, nil
	}

	removeProfileFields(classes)
	removeDeprecatedFields(objects)
	removeDeprecatedFields(classes)
	removeDTFields(objects)
	removeDTFields(classes)

	return classes, objects, types
}

func generateGoStruct(
	packageName, genDir string,
	class, objects, types map[string]interface{},
	observables []Observable) error {
	classFields, ok := class["attributes"].(map[string]interface{})
	if !ok {
		return nil
	}

	sanitizedObjectCaption := sanitizeCaption(class["caption"].(string))
	className := class["name"].(string)

	arrowFields := fmt.Sprintf("var %sFields = []arrow.Field{\n", sanitizedObjectCaption)
	goStruct := fmt.Sprintf("type %s struct {\n", sanitizedObjectCaption)

	var hasObservablesField bool
	for _, fieldName := range sortedKeys(classFields) {
		if fieldName == "observables" {
			hasObservablesField = true
		}
		fieldValue := classFields[fieldName].(map[string]interface{})

		required := fieldValue["requirement"] == "required"
		rawType := fieldValue["type"].(string)

		titleSubstrings := strings.Split(fieldName, "_")
		for idx := range titleSubstrings {
			titleSubstrings[idx] = strings.ToUpper(string(titleSubstrings[idx][0])) + titleSubstrings[idx][1:]
		}

		fieldTitle := strings.Join(titleSubstrings, "")

		var fieldType string
		var arrowType string
		var isTimestamp bool
		if rawType == "object_t" {
			if objectType, ok := fieldValue["object_type"].(string); ok && objectType != "" {
				fieldType = sanitizeCaption(objects[objectType].(map[string]interface{})["caption"].(string))
				if refTree[sanitizedObjectCaption] == nil {
					refTree[sanitizedObjectCaption] = make(map[string]bool)
				}
				refTree[sanitizedObjectCaption][fieldType] = true

				if fieldRefTree, ok := refTree[fieldType]; ok && fieldRefTree[sanitizedObjectCaption] {
					arrowType = fmt.Sprintf("%sRefStruct", fieldType)
					fieldType = fmt.Sprintf("%sRef", fieldType)
					refStructsUsed[objectType] = true
				} else {
					arrowType = fmt.Sprintf("%sStruct", fieldType)
				}
			} else {
				fieldType = "string"
				arrowType = goTypeToArrowType(fieldType)
			}
		} else if strings.HasSuffix(rawType, "_t") {
			if rawType == "date_t" {
				fieldType = "int32"
				arrowType = "arrow.FixedWidthTypes.Date32"
			} else if rawType == "timestamp_t" {
				fieldType = "int64"
				isTimestamp = true
				arrowType = "arrow.FixedWidthTypes.Timestamp_ms"
			} else {
				var err error
				fieldType, err = resolveOCSFType(rawType, types)
				if err != nil {
					log.Fatalf("Failed to resolve OCSF type: %v", err)
				}
				arrowType = goTypeToArrowType(fieldType)
			}
		} else {
			if rawType == "object" {
				fieldType = "string"
				arrowType = goTypeToArrowType(fieldType)
			} else {
				fieldType = sanitizeCaption(objects[rawType].(map[string]interface{})["caption"].(string))
				if refTree[sanitizedObjectCaption] == nil {
					refTree[sanitizedObjectCaption] = make(map[string]bool)
				}
				refTree[sanitizedObjectCaption][fieldType] = true

				if fieldRefTree, ok := refTree[fieldType]; ok && fieldRefTree[sanitizedObjectCaption] {
					arrowType = fmt.Sprintf("%sRefStruct", fieldType)
					fieldType = fmt.Sprintf("%sRef", fieldType)
					refStructsUsed[fieldValue["type"].(string)] = true
				} else {
					arrowType = fmt.Sprintf("%sStruct", fieldType)
				}
			}
		}

		if !required && !isTimestamp {
			fieldType = "*" + fieldType
		}

		var extraTags string
		if fieldValue["is_array"] == true {
			// A bug in go-parquet causes it to not handle slices of pointers.
			if !required {
				fieldType = strings.ReplaceAll(fieldType, "*", "")
			}
			fieldType = "[]" + fieldType
			arrowType = "arrow.ListOf(" + arrowType + ")"
			extraTags = ",list"
		}

		if isTimestamp {
			extraTags = ",timestamp_millis,timestamp(millisecond)"
		}

		goStruct += fmt.Sprintf("\n// %s: %s\n", fieldValue["caption"].(string), fieldValue["description"].(string))
		if required {
			goStruct += fmt.Sprintf("%s %s `json:\"%s\" parquet:\"%s%s\"`\n", fieldTitle, fieldType, fieldName, fieldName, extraTags)
			arrowFields += fmt.Sprintf("{Name: \"%s\", Type: %s, Nullable: false},\n", fieldName, arrowType)
		} else {
			goStruct += fmt.Sprintf("%s %s `json:\"%s,omitempty\" parquet:\"%s%s,optional\"`\n", fieldTitle, fieldType, fieldName, fieldName, extraTags)
			arrowFields += fmt.Sprintf("{Name: \"%s\", Type: %s, Nullable: true},\n", fieldName, arrowType)
		}
	}

	goStruct += "}\n"
	arrowFields += "}\n"

	isObservFuncBody := "return nil, \"\""
	if obs_num, ok := class["observable"].(float64); ok {
		isObservFuncBody = fmt.Sprintf("typeId := %d\nreturn &typeId, \"%s\"", int(obs_num), className)
	}

	isObservable := fmt.Sprintf(`func (v *%s) Observable() (*int, string) {
		%s
	}

	`, sanitizedObjectCaption, isObservFuncBody)

	goStruct += isObservable

	if hasObservablesField {
		validateObservables := fmt.Sprintf(`func (v *%s) ValidateObservables() error {
			presentObservables := ocsf.PresentObservablesOf(v)
			for presObsIdx := range presentObservables {
				var found bool
				for obsIdx := range v.Observables {
					presObsEnum := presentObservables[presObsIdx][0].(*int)
					if v.Observables[obsIdx].TypeId == int32(*presObsEnum) {
						found = true
						break
					}
				}
				if !found {
					obs := presentObservables[presObsIdx]
					return fmt.Errorf("non-null observable %%s(%%d) not found in observables array", obs[1], *obs[0].(*int))
				}
			}
			return nil
		}

		`, sanitizedObjectCaption)

		goStruct += validateObservables
	}

	imports := []string{"\t\"github.com/apache/arrow-go/v18/arrow\""}
	if hasObservablesField {
		imports = append(imports,
			"\t\"fmt\"",
			"\t\"github.com/telophasehq/go-ocsf/ocsf\"",
		)
	}

	fileHeader := fmt.Sprintf("\n// autogenerated by scripts/model_gen.go. DO NOT EDIT\npackage %s\n\nimport (\n%s\n)\n\n", packageName, strings.Join(imports, "\n"))

	arrowStruct := fmt.Sprintf("var %sStruct = arrow.StructOf(%sFields...)\n", sanitizedObjectCaption, sanitizedObjectCaption)
	arrowSchemaDec := fmt.Sprintf("var %sSchema = arrow.NewSchema(%sFields, nil)", sanitizedObjectCaption, sanitizedObjectCaption)
	arrowClassname := fmt.Sprintf("var %sClassname = \"%s\"\n", sanitizedObjectCaption, className)
	finalOutput := fileHeader + "\n" + goStruct + "\n" + arrowFields + "\n" + arrowStruct + "\n" + arrowSchemaDec + "\n" + arrowClassname

	filename := class["name"].(string) + ".go"

	err := os.WriteFile(genDir+"/"+filename, []byte(finalOutput), 0644)
	if err != nil {
		return err
	}

	generatedFile := fmt.Sprintf(genDir+"/%s", filename)
	if err := formatGoFile(generatedFile); err != nil {
		return err
	}

	return nil
}

func formatGoFile(filepath string) error {
	cmd := exec.Command("goimports", "-w", filepath)
	if err := cmd.Run(); err == nil {
		return nil
	}

	cmd = exec.Command("gofmt", "-w", filepath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to format file %s: goimports and gofmt both failed: %v", filepath, err)
	}

	return nil
}

func generateRefStructs(genDir string, class map[string]interface{}) error {
	filepath := genDir + "/" + class["name"].(string) + ".go"

	src, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath, src, 0)
	if err != nil {
		return err
	}

	sanitizedObjectCaption := sanitizeCaption(class["caption"].(string))

	var arrowFields, goStruct string
	ast.Inspect(file, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			return true
		}

		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) != 1 {
				continue
			}

			cl, ok := vs.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}

			if arr, ok := cl.Type.(*ast.ArrayType); ok {
				if sel, ok := arr.Elt.(*ast.SelectorExpr); ok &&
					sel.Sel.Name == "Field" {

					start := fset.Position(gd.Pos()).Offset
					end := fset.Position(cl.Rbrace).Offset + 1

					arrowFields = string(src[start:end])
					return false
				}
			}
		}
		return true
	})

	ast.Inspect(file, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			return true
		}

		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != sanitizedObjectCaption {
				continue
			}
			if _, ok := ts.Type.(*ast.StructType); !ok {
				continue
			}

			start := fset.Position(gd.Pos()).Offset
			end := fset.Position(ts.End()).Offset
			goStruct = string(src[start:end])
			return false
		}
		return true
	})

	refArrowFields := strings.Replace(arrowFields, fmt.Sprintf("%sFields", sanitizedObjectCaption), fmt.Sprintf("%sRefFields", sanitizedObjectCaption), 1)
	refGoStruct := strings.Replace(goStruct, fmt.Sprintf("%s", sanitizedObjectCaption), fmt.Sprintf("%sRef", sanitizedObjectCaption), 1)

	for refField := range refTree[sanitizedObjectCaption] {
		refArrowFields = regexp.MustCompile(fmt.Sprintf(".*Type: .*%s(Struct|RefStruct).*", refField)).ReplaceAllString(refArrowFields, "")
		refGoStruct = regexp.MustCompile(fmt.Sprintf(".*%s(Ref)?.*", refField)).ReplaceAllString(refGoStruct, "")
	}

	// The replace regex will strip the type declaration from the ref struct, so we need to add it back.
	// Go does not support negative lookaheads.
	if !strings.HasPrefix(refGoStruct, "type") {
		refGoStruct = fmt.Sprintf("type %sRef struct {\n%s", sanitizedObjectCaption, refGoStruct)
	}

	refArrowFields += fmt.Sprintf("\nvar %sRefStruct = arrow.StructOf(%sRefFields...)\n", sanitizedObjectCaption, sanitizedObjectCaption)

	f, err := os.OpenFile(
		filepath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write([]byte(refArrowFields + refGoStruct)); err != nil {
		return err
	}

	cmd := exec.Command("gofmt", "-w", filepath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to gofmt file %s: %v", filepath, err)
	}

	return nil
}

func sanitizeCaption(caption string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	return re.ReplaceAllString(caption, "")
}

func removeDeprecatedFields(jsonObjects map[string]interface{}) {
	for objectName := range jsonObjects {
		object := jsonObjects[objectName].(map[string]interface{})
		objectFields := object["attributes"].(map[string]interface{})
		for fieldName := range objectFields {
			fieldValue := objectFields[fieldName].(map[string]interface{})
			if fieldValue["@deprecated"] != nil {
				delete(objectFields, fieldName)
			}
		}
	}
}

// OCSF schema has duplicate fields for some timestamps. These fields have the suffix "_dt".
// We only keep the "time" field.
func removeDTFields(jsonObjects map[string]interface{}) {
	for objectName := range jsonObjects {
		object := jsonObjects[objectName].(map[string]interface{})
		objectFields := object["attributes"].(map[string]interface{})
		for fieldName := range objectFields {
			if strings.HasSuffix(fieldName, "_dt") {
				delete(objectFields, fieldName)
			}
		}
	}
}

func removeProfileFields(objects map[string]interface{}) {
	for objectName := range objects {
		object, ok := objects[objectName].(map[string]interface{})
		if !ok {
			continue
		}

		if object["profiles"] == nil {
			continue
		}

		objectProfiles, ok := object["profiles"].([]interface{})
		if !ok {
			continue
		}

		objectAttributes, ok := object["attributes"].(map[string]interface{})
		if !ok {
			continue
		}

		for _, objectProfileName := range objectProfiles {
			profileName, ok := objectProfileName.(string)
			if !ok {
				continue
			}

			delete(objectAttributes, profileName)
		}
	}
}

func resolveOCSFType(targetType string, types map[string]interface{}) (string, error) {
	if types[targetType] == nil {
		return "", fmt.Errorf("type %s not found", targetType)
	}

	if types[targetType].(map[string]interface{})["type"] != nil {
		ref := types[targetType].(map[string]interface{})["type"].(string)
		return resolveOCSFType(ref, types)
	}

	switch types[targetType].(map[string]interface{})["caption"].(string) {
	case "String":
		return "string", nil
	case "Long":
		return reflect.TypeOf(int64(0)).String(), nil
	case "JSON":
		return "string", nil
	case "Integer":
		return "int32", nil
	case "Float":
		return "float64", nil
	case "Boolean":
		return "bool", nil
	default:
		return "", fmt.Errorf("type %s not supported", targetType)
	}
}

func resolveObservables(current, objects map[string]interface{}, visited map[string]bool) ([]Observable, error) {
	currentName := current["name"].(string)
	var observables []Observable
	if current["observable"] != nil {
		type_id, ok := current["observable"].(float64)
		if !ok {
			return nil, fmt.Errorf("Unexpected observable type: %v, name: %s", current["observable"], currentName)
		}
		observables = append(observables, Observable{
			Name:   currentName,
			TypeID: int(type_id),
		})
	}
	if visited[currentName] {
		return nil, nil
	}

	visited[currentName] = true

	if attributes, ok := current["attributes"].(map[string]interface{}); ok {
		for attr_name := range attributes {
			attr_def, ok := attributes[attr_name].(map[string]interface{})
			if !ok {
				log.Fatalf("Not a map: %s %s", attr_name, attr_def)
			}

			attr_type := attr_def["type"].(string)
			if _, ok := objects[attr_type]; ok {
				child_obj := objects[attr_type].(map[string]interface{})
				fieldObservables, err := resolveObservables(child_obj, objects, visited)
				if err != nil {
					return nil, err
				}
				observables = append(observables, fieldObservables...)
			}
		}
	}

	return observables, nil
}

func goTypeToArrowType(targetType string) string {
	var isList bool

	if strings.HasPrefix(targetType, "[]") {
		isList = true
		targetType = strings.TrimPrefix(targetType, "[]")
	}

	targetType = strings.TrimPrefix(targetType, "*")

	switch targetType {
	case "string":
		arrowType := "arrow.BinaryTypes.String"
		if isList {
			return "arrow.ListOf(" + arrowType + ")"
		}
		return arrowType
	case "int32":
		arrowType := "arrow.PrimitiveTypes.Int32"
		if isList {
			return "arrow.ListOf(" + arrowType + ")"
		}
		return arrowType
	case "int64":
		arrowType := "arrow.PrimitiveTypes.Int64"
		if isList {
			return "arrow.ListOf(" + arrowType + ")"
		}
		return arrowType
	case "float64":
		arrowType := "arrow.PrimitiveTypes.Float64"
		if isList {
			return "arrow.ListOf(" + arrowType + ")"
		}
		return arrowType
	case "bool":
		arrowType := "arrow.FixedWidthTypes.Boolean"
		if isList {
			return "arrow.ListOf(" + arrowType + ")"
		}
		return arrowType
	default:
		panic("type " + targetType + " not supported")
	}
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
