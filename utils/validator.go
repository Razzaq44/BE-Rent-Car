package utils

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// Validator instance
var validate *validator.Validate

// InitValidator initializes the validator
func InitValidator() {
	validate = validator.New()

	// Register custom tag name function to use json tags
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
}

// ValidateStruct validates a struct and returns validation errors
func ValidateStruct(s interface{}) []string {
	var errors []string

	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			errorMsg := getErrorMessage(err)
			errors = append(errors, errorMsg)
		}
	}

	return errors
}

// BindAndValidate binds JSON request and validates it
func BindAndValidate(c *gin.Context, obj interface{}) bool {
	if err := c.ShouldBindJSON(obj); err != nil {
		SendErrorResponse(c, 400, "Invalid JSON format", err)
		return false
	}

	if validationErrors := ValidateStruct(obj); len(validationErrors) > 0 {
		SendValidationErrorResponse(c, validationErrors)
		return false
	}

	return true
}

// getErrorMessage returns a user-friendly error message for validation errors
func getErrorMessage(err validator.FieldError) string {
	fieldName := err.Field()
	tag := err.Tag()
	param := err.Param()

	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", fieldName)
	case "min":
		if err.Kind() == reflect.String {
			return fmt.Sprintf("%s must be at least %s characters long", fieldName, param)
		}
		return fmt.Sprintf("%s must be at least %s", fieldName, param)
	case "max":
		if err.Kind() == reflect.String {
			return fmt.Sprintf("%s must be at most %s characters long", fieldName, param)
		}
		return fmt.Sprintf("%s must be at most %s", fieldName, param)
	case "email":
		return fmt.Sprintf("%s must be a valid email address", fieldName)
	case "url":
		return fmt.Sprintf("%s must be a valid URL", fieldName)
	case "numeric":
		return fmt.Sprintf("%s must be a number", fieldName)
	case "alpha":
		return fmt.Sprintf("%s must contain only letters", fieldName)
	case "alphanum":
		return fmt.Sprintf("%s must contain only letters and numbers", fieldName)
	default:
		return fmt.Sprintf("%s is invalid", fieldName)
	}
}