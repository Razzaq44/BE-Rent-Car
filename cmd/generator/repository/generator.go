package repository

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

const repositoryInterfaceTemplate = `package {{.LowerName}}

import (
	"api-rentcar/models"
)

// {{.Name}}RepositoryInterface defines the contract for {{.LowerName}} data operations
type {{.Name}}RepositoryInterface interface {
	Create({{.LowerName}} *models.{{.Name}}) error
	GetByID(id uint) (*models.{{.Name}}, error)
	GetAll(page, limit int) ([]models.{{.Name}}, int64, error)
	Update({{.LowerName}} *models.{{.Name}}) error
	Delete(id uint) error
	Count() (int64, error)
	ExistsByID(id uint) (bool, error)
}
`

const repositoryImplementationTemplate = `package {{.LowerName}}

import (
	"api-rentcar/models"
	"gorm.io/gorm"
)

// {{.Name}}Repository implements {{.Name}}RepositoryInterface
type {{.Name}}Repository struct {
	db *gorm.DB
}

// New{{.Name}}Repository creates a new {{.LowerName}} repository
func New{{.Name}}Repository(db *gorm.DB) {{.Name}}RepositoryInterface {
	return &{{.Name}}Repository{
		db: db,
	}
}

// Create creates a new {{.LowerName}} in the database
func (r *{{.Name}}Repository) Create({{.LowerName}} *models.{{.Name}}) error {
	return r.db.Create({{.LowerName}}).Error
}

// GetByID retrieves a {{.LowerName}} by its ID
func (r *{{.Name}}Repository) GetByID(id uint) (*models.{{.Name}}, error) {
	var {{.LowerName}} models.{{.Name}}
	err := r.db.First(&{{.LowerName}}, id).Error
	if err != nil {
		return nil, err
	}
	return &{{.LowerName}}, nil
}

// GetAll retrieves all {{.LowerName}}s with pagination
func (r *{{.Name}}Repository) GetAll(page, limit int) ([]models.{{.Name}}, int64, error) {
	var {{.LowerName}}s []models.{{.Name}}
	var total int64

	// Count total records
	if err := r.db.Model(&models.{{.Name}}{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Calculate offset
	offset := (page - 1) * limit

	// Get paginated results
	err := r.db.Offset(offset).Limit(limit).Find(&{{.LowerName}}s).Error
	if err != nil {
		return nil, 0, err
	}

	return {{.LowerName}}s, total, nil
}

// Update updates an existing {{.LowerName}}
func (r *{{.Name}}Repository) Update({{.LowerName}} *models.{{.Name}}) error {
	return r.db.Save({{.LowerName}}).Error
}

// Delete deletes a {{.LowerName}} by its ID
func (r *{{.Name}}Repository) Delete(id uint) error {
	return r.db.Delete(&models.{{.Name}}{}, id).Error
}

// Count returns the total number of {{.LowerName}}s
func (r *{{.Name}}Repository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.{{.Name}}{}).Count(&count).Error
	return count, err
}

// ExistsByID checks if a {{.LowerName}} exists by its ID
func (r *{{.Name}}Repository) ExistsByID(id uint) (bool, error) {
	var count int64
	err := r.db.Model(&models.{{.Name}}{}).Where("id = ?", id).Count(&count).Error
	return count > 0, err
}
`

// GenerateInterface creates the repository interface file
func GenerateInterface(data GeneratorData) error {
	// Create repository directory if it doesn't exist
	repoDir := filepath.Join("repositories", data.LowerName)
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		return fmt.Errorf("failed to create repository directory: %v", err)
	}

	// Create repository interface file
	interfaceFile := filepath.Join(repoDir, fmt.Sprintf("%s_repository_interface.go", data.LowerName))
	file, err := os.Create(interfaceFile)
	if err != nil {
		return fmt.Errorf("failed to create repository interface file: %v", err)
	}
	defer file.Close()

	// Parse and execute template
	tmpl, err := template.New("repositoryInterface").Parse(repositoryInterfaceTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse repository interface template: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute repository interface template: %v", err)
	}

	return nil
}

// GenerateImplementation creates the repository implementation file
func GenerateImplementation(data GeneratorData) error {
	// Create repository directory if it doesn't exist
	repoDir := filepath.Join("repositories", data.LowerName)
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		return fmt.Errorf("failed to create repository directory: %v", err)
	}

	// Create repository implementation file
	implFile := filepath.Join(repoDir, fmt.Sprintf("%s_repository.go", data.LowerName))
	file, err := os.Create(implFile)
	if err != nil {
		return fmt.Errorf("failed to create repository implementation file: %v", err)
	}
	defer file.Close()

	// Parse and execute template
	tmpl, err := template.New("repositoryImplementation").Parse(repositoryImplementationTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse repository implementation template: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute repository implementation template: %v", err)
	}

	return nil
}