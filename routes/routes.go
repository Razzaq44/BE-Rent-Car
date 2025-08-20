package routes

import (
	"api-rentcar/controllers"
	"api-rentcar/middleware"
	"api-rentcar/repositories/car"
	"api-rentcar/repositories/product"
	"api-rentcar/services"

	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// SetupRoutes configures all application routes
func SetupRoutes(router *gin.Engine, db *gorm.DB) {
	// Initialize repository
	productRepo := product.NewProductRepository(db)
	carRepo := car.NewCarRepository(db)

	// Initialize service
	productService := services.NewProductService(productRepo)
	carService := services.NewCarService(carRepo)

	// Initialize controllers
	productController := controllers.NewProductController(productService)
	carController := controllers.NewCarController(carService)

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"message": "API is running",
			"version": "1.0.0",
		})
	})

	// Swagger documentation
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Apply middleware to API routes
		v1.Use(middleware.RequestID())
		v1.Use(middleware.RateLimiter())

		// Product routes
		products := v1.Group("/products")
		{
			products.POST("", productController.CreateProduct)
			products.GET("", productController.GetProducts)
			products.GET("/:id", productController.GetProduct)
			products.PUT("/:id", productController.UpdateProduct)
			products.DELETE("/:id", productController.DeleteProduct)
		}

		// Car routes
		cars := v1.Group("/cars")
		{
			cars.POST("", carController.CreateCar)
			cars.GET("", carController.GetCars)
			cars.GET("/:id", carController.GetCar)
			cars.PUT("/:id", carController.UpdateCar)
			cars.DELETE("/:id", carController.DeleteCar)
		}
	}

	// 404 handler
	router.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{
			"success": false,
			"message": "Route not found",
			"error":   "The requested endpoint does not exist",
		})
	})
}
