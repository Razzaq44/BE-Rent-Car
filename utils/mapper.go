package utils

import (
	"reflect"
	"strings"
)

// MapFields maps fields from source struct to destination struct using reflection
// This function automatically maps fields with matching names and compatible types
func MapFields(src any, dst any) {
	srcValue := reflect.ValueOf(src)
	dstValue := reflect.ValueOf(dst)

	// Handle pointers
	if srcValue.Kind() == reflect.Ptr {
		srcValue = srcValue.Elem()
	}
	if dstValue.Kind() == reflect.Ptr {
		dstValue = dstValue.Elem()
	}

	// Ensure both are structs
	if srcValue.Kind() != reflect.Struct || dstValue.Kind() != reflect.Struct {
		return
	}

	srcType := srcValue.Type()
	dstType := dstValue.Type()

	// Create a map of destination field names for quick lookup
	dstFields := make(map[string]reflect.Value)
	for i := 0; i < dstValue.NumField(); i++ {
		field := dstValue.Field(i)
		fieldType := dstType.Field(i)
		if field.CanSet() {
			dstFields[fieldType.Name] = field
		}
	}

	// Map fields from source to destination
	for i := 0; i < srcValue.NumField(); i++ {
		srcField := srcValue.Field(i)
		srcFieldType := srcType.Field(i)
		fieldName := srcFieldType.Name

		// Skip unexported fields
		if !srcField.CanInterface() {
			continue
		}

		// Find matching destination field
		if dstField, exists := dstFields[fieldName]; exists {
			// Handle pointer fields in source (for update requests)
			if srcField.Kind() == reflect.Ptr {
				if !srcField.IsNil() {
					srcFieldValue := srcField.Elem()
					if srcFieldValue.Type().AssignableTo(dstField.Type()) {
						dstField.Set(srcFieldValue)
					}
				}
			} else {
				// Direct assignment for non-pointer fields
				if srcField.Type().AssignableTo(dstField.Type()) {
					dstField.Set(srcField)
				}
			}
		}
	}
}

// MapFieldsWithExclusions maps fields from source to destination, excluding specified fields
func MapFieldsWithExclusions(src interface{}, dst interface{}, excludeFields ...string) {
	excludeMap := make(map[string]bool)
	for _, field := range excludeFields {
		excludeMap[field] = true
	}

	srcValue := reflect.ValueOf(src)
	dstValue := reflect.ValueOf(dst)

	// Handle pointers
	if srcValue.Kind() == reflect.Ptr {
		srcValue = srcValue.Elem()
	}
	if dstValue.Kind() == reflect.Ptr {
		dstValue = dstValue.Elem()
	}

	// Ensure both are structs
	if srcValue.Kind() != reflect.Struct || dstValue.Kind() != reflect.Struct {
		return
	}

	srcType := srcValue.Type()
	dstType := dstValue.Type()

	// Create a map of destination field names for quick lookup
	dstFields := make(map[string]reflect.Value)
	for i := 0; i < dstValue.NumField(); i++ {
		field := dstValue.Field(i)
		fieldType := dstType.Field(i)
		if field.CanSet() && !excludeMap[fieldType.Name] {
			dstFields[fieldType.Name] = field
		}
	}

	// Map fields from source to destination
	for i := 0; i < srcValue.NumField(); i++ {
		srcField := srcValue.Field(i)
		srcFieldType := srcType.Field(i)
		fieldName := srcFieldType.Name

		// Skip excluded fields
		if excludeMap[fieldName] {
			continue
		}

		// Skip unexported fields
		if !srcField.CanInterface() {
			continue
		}

		// Find matching destination field
		if dstField, exists := dstFields[fieldName]; exists {
			// Handle pointer fields in source (for update requests)
			if srcField.Kind() == reflect.Ptr {
				if !srcField.IsNil() {
					srcFieldValue := srcField.Elem()
					if srcFieldValue.Type().AssignableTo(dstField.Type()) {
						dstField.Set(srcFieldValue)
					}
				}
			} else {
				// Direct assignment for non-pointer fields
				if srcField.Type().AssignableTo(dstField.Type()) {
					dstField.Set(srcField)
				}
			}
		}
	}
}

// GetStructFieldNames returns all field names of a struct
func GetStructFieldNames(s any) []string {
	v := reflect.ValueOf(s)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return nil
	}

	t := v.Type()
	fields := make([]string, 0, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		// Skip unexported fields
		if field.PkgPath == "" {
			fields = append(fields, field.Name)
		}
	}

	return fields
}

// HasField checks if a struct has a specific field
func HasField(s any, fieldName string) bool {
	v := reflect.ValueOf(s)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return false
	}

	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if strings.EqualFold(field.Name, fieldName) {
			return true
		}
	}

	return false
}
