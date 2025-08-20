package service

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

const serviceTemplate = `package services

import (
	"errors"
	"api-rentcar/models"
	requests "api-rentcar/requests"
	{{.LowerName}}Repo "api-rentcar/repositories/{{.LowerName}}"
	"api-rentcar/utils"
	"gorm.io/gorm"
)

// {{.Name}}ServiceInterface defines the contract for {{.LowerName}} business logic
type {{.Name}}ServiceInterface interface {
	Create{{.Name}}(req *requests.Create{{.Name}}Request) (*models.{{.Name}}, error)
	Get{{.Name}}ByID(id uint) (*models.{{.Name}}, error)
	Get{{.Name}}s(page, limit int) ([]models.{{.Name}}, int64, error)
	Update{{.Name}}(id uint, req *requests.Update{{.Name}}Request) (*models.{{.Name}}, error)
	Delete{{.Name}}(id uint) error
	Get{{.Name}}Stats() (map[string]interface{}, error)
}

// {{.Name}}Service implements {{.Name}}ServiceInterface
type {{.Name}}Service struct {
	{{.LowerName}}Repo {{.LowerName}}Repo.{{.Name}}RepositoryInterface
}

// New{{.Name}}Service creates a new {{.LowerName}} service
func New{{.Name}}Service({{.LowerName}}Repo {{.LowerName}}Repo.{{.Name}}RepositoryInterface) {{.Name}}ServiceInterface {
	return &{{.Name}}Service{
		{{.LowerName}}Repo: {{.LowerName}}Repo,
	}
}

// Create{{.Name}} creates a new {{.LowerName}} with business logic validation
func (s *{{.Name}}Service) Create{{.Name}}(req *requests.Create{{.Name}}Request) (*models.{{.Name}}, error) {
	{{.LowerName}} := &models.{{.Name}}{}
	
	// Use reflection-based field mapping for automatic assignment
	utils.MapFields(req, {{.LowerName}})

	if err := s.{{.LowerName}}Repo.Create({{.LowerName}}); err != nil {
		return nil, err
	}

	return {{.LowerName}}, nil
}

// Get{{.Name}}ByID retrieves a {{.LowerName}} by its ID
func (s *{{.Name}}Service) Get{{.Name}}ByID(id uint) (*models.{{.Name}}, error) {
	if id == 0 {
		return nil, errors.New("invalid {{.LowerName}} ID")
	}

	{{.LowerName}}, err := s.{{.LowerName}}Repo.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("{{.LowerName}} not found")
		}
		return nil, err
	}

	return {{.LowerName}}, nil
}

// Get{{.Name}}s retrieves all {{.LowerName}}s with pagination
func (s *{{.Name}}Service) Get{{.Name}}s(page, limit int) ([]models.{{.Name}}, int64, error) {
	// Business logic: validate pagination parameters
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	{{.LowerName}}s, total, err := s.{{.LowerName}}Repo.GetAll(page, limit)
	if err != nil {
		return nil, 0, err
	}

	return {{.LowerName}}s, total, nil
}

// Update{{.Name}} updates an existing {{.LowerName}}
func (s *{{.Name}}Service) Update{{.Name}}(id uint, req *requests.Update{{.Name}}Request) (*models.{{.Name}}, error) {
	// Check if {{.LowerName}} exists
	existing{{.Name}}, err := s.{{.LowerName}}Repo.GetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("{{.LowerName}} not found")
		}
		return nil, err
	}

	// Use reflection-based field mapping for automatic assignment
	// This will handle all pointer fields automatically
	utils.MapFieldsWithExclusions(req, existing{{.Name}}, "ID", "CreatedAt", "UpdatedAt", "DeletedAt")

	if err := s.{{.LowerName}}Repo.Update(existing{{.Name}}); err != nil {
		return nil, err
	}

	return existing{{.Name}}, nil
}

// Delete{{.Name}} deletes a {{.LowerName}} by its ID
func (s *{{.Name}}Service) Delete{{.Name}}(id uint) error {
	// Check if {{.LowerName}} exists
	exists, err := s.{{.LowerName}}Repo.ExistsByID(id)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("{{.LowerName}} not found")
	}

	return s.{{.LowerName}}Repo.Delete(id)
}

// Get{{.Name}}Stats returns statistics about {{.LowerName}}s
func (s *{{.Name}}Service) Get{{.Name}}Stats() (map[string]interface{}, error) {
	total, err := s.{{.LowerName}}Repo.Count()
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_{{.LowerName}}s": total,
	}

	return stats, nil
}
`

// Generate creates the service file
func Generate(data GeneratorData) error {
	// Create services directory if it doesn't exist
	servicesDir := "services"
	if err := os.MkdirAll(servicesDir, 0755); err != nil {
		return fmt.Errorf("failed to create services directory: %v", err)
	}

	// Create service file
	serviceFile := filepath.Join(servicesDir, fmt.Sprintf("%s_service.go", data.LowerName))
	file, err := os.Create(serviceFile)
	if err != nil {
		return fmt.Errorf("failed to create service file: %v", err)
	}
	defer file.Close()

	// Parse and execute template
	tmpl, err := template.New("service").Parse(serviceTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse service template: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute service template: %v", err)
	}

	return nil
}