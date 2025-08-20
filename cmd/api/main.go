package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"api-rentcar/config"
	_ "api-rentcar/docs"
	"api-rentcar/middleware"
	"api-rentcar/routes"
	"api-rentcar/utils"

	"github.com/gin-gonic/gin"
)

// @title RESTful API GO
// @version 1.0
// @description A RESTful API management system
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /api/v1

// @schemes http https

func main() {
	// Load configuration
	if err := config.LoadConfig(); err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Initialize database
	if err := config.InitDatabase(); err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer func() {
		if err := config.CloseDatabase(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Initialize validator
	utils.InitValidator()

	// Set Gin mode
	gin.SetMode(config.AppConfig.GinMode)

	// Create Gin router
	router := gin.New()

	// Apply global middleware
	router.Use(middleware.Logger())
	router.Use(middleware.Recovery())
	router.Use(middleware.CORS())
	router.Use(middleware.SecurityHeaders())

	// Setup routes
	routes.SetupRoutes(router, config.GetDB())

	// Create HTTP server
	server := &http.Server{
		Addr:           ":" + config.AppConfig.Port,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting server on port %s", config.AppConfig.Port)
		log.Printf("Swagger documentation available at: http://localhost:%s/swagger/index.html", config.AppConfig.Port)
		log.Printf("Health check available at: http://localhost:%s/health", config.AppConfig.Port)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Give outstanding requests a deadline for completion
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}
