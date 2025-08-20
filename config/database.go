package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"api-rentcar/models"
)

var DB *gorm.DB

func InitDatabase() error {
	var err error

	switch AppConfig.DBType {
	case "sqlite":
		dbPath := os.Getenv("DB_PATH")
		if dbPath == "" {
			dbPath = "./data/rentcar.db"
		}

		// Create data directory if it doesn't exist
		dataDir := filepath.Dir(dbPath)
		if mkdirErr := os.MkdirAll(dataDir, 0755); mkdirErr != nil {
			return fmt.Errorf("failed to create data directory: %w", err)
		}

		// Configure GORM logger
		logLevel := logger.Info
		if os.Getenv("GIN_MODE") == "release" {
			logLevel = logger.Error
		}

		config := &gorm.Config{
			Logger: logger.Default.LogMode(logLevel),
		}

		// Open database connection with pure Go SQLite driver
		dsn := dbPath + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=temp_store(memory)&_pragma=mmap_size(268435456)"
		DB, err = gorm.Open(sqlite.Open(dsn), config)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}

		// Run auto migrations
		err = runMigrations()
		if err != nil {
			return fmt.Errorf("failed to run migrations: %w", err)
		}

		log.Println("Database initialized successfully")
		return nil
	case "mysql":
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			os.Getenv("DB_USER"),
			os.Getenv("DB_PASSWORD"),
			os.Getenv("DB_HOST"),
			os.Getenv("DB_PORT"),
			os.Getenv("DB_NAME"),
		)
		DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			return fmt.Errorf("failed to connect to MySQL database: %w", err)
		}
		log.Println("Connected to MySQL database")
	default:
		return fmt.Errorf("unsupported database type: %s", AppConfig.DBType)
	}

	// Auto-migrate your models
	err = DB.AutoMigrate(&models.Product{}, &models.Car{})
	if err != nil {
		return fmt.Errorf("failed to auto-migrate database: %w", err)
	}
	log.Println("Database initialized successfully")

	return nil
}

// runMigrations runs database migrations for all models
func runMigrations() error {
	return DB.AutoMigrate(
		&models.Product{},
		&models.Car{},
	)
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return DB
}

// CloseDatabase closes the database connection
func CloseDatabase() error {
	if DB != nil {
		sqlDB, err := DB.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}
