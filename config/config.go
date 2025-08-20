package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// JWTConfig holds JWT-related configuration
type JWTConfig struct {
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Secret             string
	RefreshSecret      string
	Issuer             string
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	ValidateIP           bool
	MaxLoginAttempts     int
	LockoutDuration      time.Duration
	BcryptCost           int
	PasswordResetExpiry  time.Duration
	EmailVerificationExpiry time.Duration
}

// Config holds all configuration for the application
type Config struct {
	Port       string
	GinMode    string
	DBType     string
	DBPath     string
	APIVersion string
	APITitle   string
	APIDesc    string
	
	// Nested configurations
	JWT      JWTConfig
	Security SecurityConfig
	
	// Rate Limiting
	RateLimitRequests      int
	RateLimitWindow        string
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
		
		// JWT Configuration
		JWT: JWTConfig{
			AccessTokenExpiry:  getEnvAsDuration("JWT_ACCESS_TOKEN_EXPIRY", "15m"),
			RefreshTokenExpiry: getEnvAsDuration("JWT_REFRESH_TOKEN_EXPIRY", "720h"), // 30 days
			Secret:             getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production"),
			RefreshSecret:      getEnv("JWT_REFRESH_SECRET", "your-super-secret-jwt-refresh-key-change-this-in-production"),
			Issuer:             getEnv("JWT_ISSUER", "rentcar-api"),
		},
		
		// Security Configuration
		Security: SecurityConfig{
			ValidateIP:              getEnvAsBool("SECURITY_VALIDATE_IP", false),
			MaxLoginAttempts:        getEnvAsInt("MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:         getEnvAsDuration("ACCOUNT_LOCK_DURATION", "30m"),
			BcryptCost:              getEnvAsInt("BCRYPT_COST", 12),
			PasswordResetExpiry:     getEnvAsDuration("PASSWORD_RESET_EXPIRY", "1h"),
			EmailVerificationExpiry: getEnvAsDuration("EMAIL_VERIFICATION_EXPIRY", "24h"),
		},
		
		// Rate Limiting
		RateLimitRequests:      getEnvAsInt("RATE_LIMIT_REQUESTS", 100),
		RateLimitWindow:        getEnv("RATE_LIMIT_WINDOW", "1h"),
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

// getEnvAsInt gets an environment variable as integer with a fallback value
func getEnvAsInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return fallback
}

// getEnvAsDuration gets an environment variable as time.Duration with a fallback value
func getEnvAsDuration(key, fallback string) time.Duration {
	value := getEnv(key, fallback)
	if duration, err := time.ParseDuration(value); err == nil {
		return duration
	}
	// If parsing fails, try to parse the fallback
	if duration, err := time.ParseDuration(fallback); err == nil {
		return duration
	}
	// If both fail, return a default duration
	return 15 * time.Minute
}

// getEnvAsBool gets an environment variable as boolean with a fallback value
func getEnvAsBool(key string, fallback bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return fallback
}
