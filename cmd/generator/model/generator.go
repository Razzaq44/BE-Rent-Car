package model

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

type GeneratorData struct {
	Name      string // e.g., "User"
	LowerName string // e.g., "user"
}

const modelTemplate = `package models

import (
	"gorm.io/gorm"
	"time"
)

// {{.Name}} represents the {{.LowerName}} entity in the database
// @Description {{.Name}} entity model
type {{.Name}} struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint ` + "`gorm:\"primaryKey;autoIncrement\" json:\"id\" example:\"1\"`" + `

	// Name of the {{.LowerName}}
	// @Description Name of the {{.LowerName}}
	// @Example "Sample {{.Name}}"
	Name string ` + "`gorm:\"type:varchar(100);not null;index\" json:\"name\" validate:\"required,min=3,max=100\" example:\"Sample {{.Name}}\"`" + `

	// Description of the {{.LowerName}}
	// @Description Description of the {{.LowerName}}
	// @Example "This is a sample {{.LowerName}} description"
	Description string ` + "`gorm:\"type:text\" json:\"description\" validate:\"required,min=10,max=500\" example:\"This is a sample {{.LowerName}} description\"`" + `

	// Timestamps
	// @Description Creation timestamp
	// @Example "2023-01-01T00:00:00Z"
	CreatedAt time.Time ` + "`gorm:\"autoCreateTime\" json:\"created_at\" example:\"2023-01-01T00:00:00Z\"`" + `

	// @Description Last update timestamp
	// @Example "2023-01-01T00:00:00Z"
	UpdatedAt time.Time ` + "`gorm:\"autoUpdateTime\" json:\"updated_at\" example:\"2023-01-01T00:00:00Z\"`" + `

	// @Description Soft delete timestamp
	// DeletedAt gorm.DeletedAt ` + "`gorm:\"index\" json:\"deleted_at,omitempty\"`" + `

	// Add other fields as needed
}

// TableName returns the table name for the {{.Name}} model
func ({{.Name}}) TableName() string {
	return "{{.LowerName}}s"
}

// BeforeCreate is a GORM hook that runs before creating a {{.LowerName}}
func ({{.LowerName}} *{{.Name}}) BeforeCreate(tx *gorm.DB) error {
	// Add any pre-creation logic here
	return nil
}

// BeforeUpdate is a GORM hook that runs before updating a {{.LowerName}}
func ({{.LowerName}} *{{.Name}}) BeforeUpdate(tx *gorm.DB) error {
	// Add any pre-update logic here
	return nil
}

// AfterCreate is a GORM hook that runs after creating a {{.LowerName}}
func ({{.LowerName}} *{{.Name}}) AfterCreate(tx *gorm.DB) error {
	// Add any post-creation logic here
	return nil
}

// AfterUpdate is a GORM hook that runs after updating a {{.LowerName}}
func ({{.LowerName}} *{{.Name}}) AfterUpdate(tx *gorm.DB) error {
	// Add any post-update logic here
	return nil
}

// BeforeDelete is a GORM hook that runs before deleting a {{.LowerName}}
func ({{.LowerName}} *{{.Name}}) BeforeDelete(tx *gorm.DB) error {
	// Add any pre-deletion logic here
	return nil
}

// AfterDelete is a GORM hook that runs after deleting a {{.LowerName}}
func ({{.LowerName}} *{{.Name}}) AfterDelete(tx *gorm.DB) error {
	// Add any post-deletion logic here
	return nil
}
`

// Generate creates the model file
func Generate(data GeneratorData) error {
	// Create models directory if it doesn't exist
	modelsDir := "models"
	if err := os.MkdirAll(modelsDir, 0755); err != nil {
		return fmt.Errorf("failed to create models directory: %v", err)
	}

	// Create model file
	modelFile := filepath.Join(modelsDir, fmt.Sprintf("%s.go", data.LowerName))
	file, err := os.Create(modelFile)
	if err != nil {
		return fmt.Errorf("failed to create model file: %v", err)
	}
	defer file.Close()

	// Parse and execute template
	tmpl, err := template.New("model").Parse(modelTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse model template: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute model template: %v", err)
	}

	return nil
}