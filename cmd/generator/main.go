package main

import (
	"fmt"
	"os"
	"strings"

	"api-rentcar/cmd/generator/controller"
	"api-rentcar/cmd/generator/model"
	"api-rentcar/cmd/generator/repository"
	"api-rentcar/cmd/generator/request"
	"api-rentcar/cmd/generator/response"
	"api-rentcar/cmd/generator/service"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/generator/main.go <EntityName>")
		fmt.Println("Example: go run cmd/generator/main.go User")
		os.Exit(1)
	}

	entityName := os.Args[1]
	lowerName := strings.ToLower(entityName)

	fmt.Printf("Generating files for entity: %s\n", entityName)
	fmt.Println("========================================")

	// Generate Controller
	fmt.Println("Generating Controller...")
	controllerData := controller.GeneratorData{
		Name:      entityName,
		LowerName: lowerName,
	}
	if err := controller.Generate(controllerData); err != nil {
		fmt.Printf("Error generating Controller: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Controller generated successfully")

	// Generate Repository Interface
	fmt.Println("Generating Repository Interface...")
	repoData := repository.GeneratorData{
		Name:      entityName,
		LowerName: lowerName,
	}
	if err := repository.GenerateInterface(repoData); err != nil {
		fmt.Printf("Error generating Repository Interface: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Repository Interface generated successfully")

	// Generate Repository Implementation
	fmt.Println("Generating Repository Implementation...")
	if err := repository.GenerateImplementation(repoData); err != nil {
		fmt.Printf("Error generating Repository Implementation: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Repository Implementation generated successfully")

	// Generate Service
	fmt.Println("Generating Service...")
	serviceData := service.GeneratorData{
		Name:      entityName,
		LowerName: lowerName,
	}
	if err := service.Generate(serviceData); err != nil {
		fmt.Printf("Error generating Service: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Service generated successfully")

	// Generate Request
	fmt.Println("Generating Request...")
	requestData := request.GeneratorData{
		Name:      entityName,
		LowerName: lowerName,
	}
	if err := request.Generate(requestData); err != nil {
		fmt.Printf("Error generating Request: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Request generated successfully")

	// Generate Response
	fmt.Println("Generating Response...")
	responseData := response.GeneratorData{
		Name:      entityName,
		LowerName: lowerName,
	}
	if err := response.Generate(responseData); err != nil {
		fmt.Printf("Error generating Response: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Response generated successfully")

	// Generate Model
	fmt.Println("Generating Model...")
	modelData := model.GeneratorData{
		Name:      entityName,
		LowerName: lowerName,
	}
	if err := model.Generate(modelData); err != nil {
		fmt.Printf("Error generating Model: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓ Model generated successfully")

	fmt.Println("\n========================================")
	fmt.Println("All files generated successfully!")
	fmt.Printf("\nGenerated files for entity '%s':\n", entityName)
	fmt.Printf("- controllers/%s_controller.go\n", lowerName)
	fmt.Printf("- repositories/%s/interface.go\n", lowerName)
	fmt.Printf("- repositories/%s/repository.go\n", lowerName)
	fmt.Printf("- services/%s_service.go\n", lowerName)
	fmt.Printf("- requests/%s_request.go\n", lowerName)
	fmt.Printf("- responses/%s_response.go\n", lowerName)
	fmt.Printf("- models/%s.go\n", lowerName)
	fmt.Println("\nYou can now use these files in your application!")
}