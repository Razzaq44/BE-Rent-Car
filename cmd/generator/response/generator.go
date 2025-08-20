package response

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

const responseTemplate = `package responses

import (
	"api-rentcar/models"
	"api-rentcar/utils"
	"time"
)

// {{.Name}}Response represents a single {{.LowerName}} response
// @Description {{.Name}} response structure
type {{.Name}}Response struct {
	// Primary key
	// @Description Unique identifier
	// @Example 1
	ID uint ` + "`json:\"id\" example:\"1\"`" + `

	// Name of the {{.LowerName}}
	// @Description Name of the {{.LowerName}}
	// @Example "Sample {{.Name}}"
	Name string ` + "`json:\"name\" example:\"Sample {{.Name}}\"`" + `

	// Description of the {{.LowerName}}
	// @Description Description of the {{.LowerName}}
	// @Example "This is a sample {{.LowerName}} description"
	Description string ` + "`json:\"description\" example:\"This is a sample {{.LowerName}} description\"`" + `

	// Creation timestamp
	// @Description Creation timestamp
	// @Example "2023-01-01T00:00:00Z"
	CreatedAt time.Time ` + "`json:\"created_at\" example:\"2023-01-01T00:00:00Z\"`" + `

	// Last update timestamp
	// @Description Last update timestamp
	// @Example "2023-01-01T00:00:00Z"
	UpdatedAt time.Time ` + "`json:\"updated_at\" example:\"2023-01-01T00:00:00Z\"`" + `

	// Add other fields as needed
}

// {{.Name}}sListResponse represents a paginated list of {{.LowerName}}s
// @Description Paginated {{.LowerName}}s list response
type {{.Name}}sListResponse struct {
	// List of {{.LowerName}}s
	// @Description Array of {{.LowerName}} objects
	Data []{{.Name}}Response ` + "`json:\"data\"`" + `

	// Pagination metadata
	// @Description Pagination information
	Pagination utils.PaginationMeta ` + "`json:\"pagination\"`" + `
}

// To{{.Name}}Response converts a {{.Name}} model to {{.Name}}Response
func To{{.Name}}Response({{.LowerName}} *models.{{.Name}}) {{.Name}}Response {
	return {{.Name}}Response{
		ID:          {{.LowerName}}.ID,
		Name:        {{.LowerName}}.Name,
		Description: {{.LowerName}}.Description,
		CreatedAt:   {{.LowerName}}.CreatedAt,
		UpdatedAt:   {{.LowerName}}.UpdatedAt,
		// Add other field mappings as needed
	}
}

// To{{.Name}}sListResponse converts a slice of {{.Name}} models to {{.Name}}sListResponse with pagination
func To{{.Name}}sListResponse({{.LowerName}}s []models.{{.Name}}, total int64, page, limit int) {{.Name}}sListResponse {
	{{.LowerName}}Responses := make([]{{.Name}}Response, len({{.LowerName}}s))
	for i, {{.LowerName}} := range {{.LowerName}}s {
		{{.LowerName}}Responses[i] = To{{.Name}}Response(&{{.LowerName}})
	}

	return {{.Name}}sListResponse{
		Data: {{.LowerName}}Responses,
		Pagination: utils.CreatePaginationMeta(total, page, limit),
	}
}
`

// Generate creates the response file
func Generate(data GeneratorData) error {
	// Create responses directory if it doesn't exist
	responsesDir := "responses"
	if err := os.MkdirAll(responsesDir, 0755); err != nil {
		return fmt.Errorf("failed to create responses directory: %v", err)
	}

	// Create response file
	responseFile := filepath.Join(responsesDir, fmt.Sprintf("%s.go", data.LowerName))
	file, err := os.Create(responseFile)
	if err != nil {
		return fmt.Errorf("failed to create response file: %v", err)
	}
	defer file.Close()

	// Parse and execute template
	tmpl, err := template.New("response").Parse(responseTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse response template: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute response template: %v", err)
	}

	return nil
}