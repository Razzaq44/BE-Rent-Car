package request

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

const requestTemplate = `package requests

import (
	"github.com/go-playground/validator/v10"
)

// Create{{.Name}}Request represents the request payload for creating a new {{.LowerName}}
// @Description Request payload for creating a new {{.LowerName}}
type Create{{.Name}}Request struct {
	// Name of the {{.LowerName}}
	// @Description Name of the {{.LowerName}}
	// @Example "Sample {{.Name}}"
	Name string ` + "`json:\"name\" validate:\"required,min=3,max=100\" example:\"Sample {{.Name}}\"`" + `

	// Description of the {{.LowerName}}
	// @Description Description of the {{.LowerName}}
	// @Example "This is a sample {{.LowerName}} description"
	Description string ` + "`json:\"description\" validate:\"required,min=10,max=500\" example:\"This is a sample {{.LowerName}} description\"`" + `

	// Add other fields as needed
}

// Validate validates the Create{{.Name}}Request
func (r *Create{{.Name}}Request) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}

// Update{{.Name}}Request represents the request payload for updating a {{.LowerName}}
// @Description Request payload for updating a {{.LowerName}}
type Update{{.Name}}Request struct {
	// Name of the {{.LowerName}}
	// @Description Name of the {{.LowerName}}
	// @Example "Updated {{.Name}}"
	Name *string ` + "`json:\"name,omitempty\" validate:\"omitempty,min=3,max=100\" example:\"Updated {{.Name}}\"`" + `

	// Description of the {{.LowerName}}
	// @Description Description of the {{.LowerName}}
	// @Example "This is an updated {{.LowerName}} description"
	Description *string ` + "`json:\"description,omitempty\" validate:\"omitempty,min=10,max=500\" example:\"This is an updated {{.LowerName}} description\"`" + `

	// Add other fields as needed
}

// Validate validates the Update{{.Name}}Request
func (r *Update{{.Name}}Request) Validate() error {
	validate := validator.New()
	return validate.Struct(r)
}
`

// Generate creates the request file
func Generate(data GeneratorData) error {
	// Create requests directory if it doesn't exist
	requestsDir := "requests"
	if err := os.MkdirAll(requestsDir, 0755); err != nil {
		return fmt.Errorf("failed to create requests directory: %v", err)
	}

	// Create request file
	requestFile := filepath.Join(requestsDir, fmt.Sprintf("%s.go", data.LowerName))
	file, err := os.Create(requestFile)
	if err != nil {
		return fmt.Errorf("failed to create request file: %v", err)
	}
	defer file.Close()

	// Parse and execute template
	tmpl, err := template.New("request").Parse(requestTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse request template: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute request template: %v", err)
	}

	return nil
}