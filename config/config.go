package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	Port       string
	GinMode    string
	DBType     string
	DBPath     string
	APIVersion string
	APITitle   string
	APIDesc    string
}

// AppConfig is the global configuration instance
var AppConfig *Config

// LoadConfig loads configuration from environment variables
func LoadConfig() error {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	AppConfig = &Config{
		Port:       getEnv("PORT", "8080"),
		GinMode:    getEnv("GIN_MODE", "debug"),
		DBType:     getEnv("DB_TYPE", "sqlite"),
		DBPath:     getEnv("DB_PATH", "./data/rentcar.db"),
		APIVersion: getEnv("API_VERSION", "v1"),
		APITitle:   getEnv("API_TITLE", "RentCar API"),
		APIDesc:    getEnv("API_DESCRIPTION", "A RESTful API for car rental management"),
	}

	log.Printf("Configuration loaded: Port=%s, Mode=%s, DB=%s",
		AppConfig.Port, AppConfig.GinMode, AppConfig.DBPath)

	return nil
}

// getEnv gets an environment variable with a fallback value
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
