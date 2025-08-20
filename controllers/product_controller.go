package controllers

import (
	"net/http"
	"strconv"

	requests "api-rentcar/requests"
	"api-rentcar/services"
	"api-rentcar/utils"
	"github.com/gin-gonic/gin"
)

// ProductController handles product related requests
type ProductController struct {
	productService services.ProductServiceInterface
}

// NewProductController creates a new product controller
func NewProductController(productService services.ProductServiceInterface) *ProductController {
	return &ProductController{
		productService: productService,
	}
}

// CreateProduct godoc
// @Summary Create a new product
// @Description Create a new product with the provided information
// @Tags products
// @Accept json
// @Produce json
// @Param product body requests.CreateProductRequest true "Product creation request"
// @Success 201 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /products [post]
func (c *ProductController) CreateProduct(ctx *gin.Context) {
	var req requests.CreateProductRequest
	if !utils.BindAndValidate(ctx, &req) {
		return
	}

	product, err := c.productService.CreateProduct(&req)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to create product", err)
		return
	}

	utils.SendSuccessResponse(ctx, http.StatusCreated, "Product created successfully", product)
}

// GetProducts godoc
// @Summary Get all products
// @Description Get a list of products with optional pagination and filtering
// @Tags products
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} utils.SuccessResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /products [get]
func (c *ProductController) GetProducts(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(ctx.DefaultQuery("limit", "10"))

	products, total, err := c.productService.GetProducts(page, limit)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to fetch products", err)
		return
	}

	utils.SendPaginatedResponse(ctx, "Products retrieved successfully", products, total, page, limit)
}

// GetProduct godoc
// @Summary Get a product by ID
// @Description Get a single product by its ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /products/{id} [get]
func (c *ProductController) GetProduct(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusBadRequest, "Invalid product ID", err)
		return
	}

	product, err := c.productService.GetProductByID(uint(id))
	if err != nil {
		if err.Error() == "product not found" {
			utils.SendErrorResponse(ctx, http.StatusNotFound, "Product not found", err)
			return
		}
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to fetch product", err)
		return
	}

	utils.SendSuccessResponse(ctx, http.StatusOK, "Product retrieved successfully", product)
}

// UpdateProduct godoc
// @Summary Update a product
// @Description Update an existing product with the provided information
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Param product body requests.UpdateProductRequest true "Product update request"
// @Success 200 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /products/{id} [put]
func (c *ProductController) UpdateProduct(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusBadRequest, "Invalid product ID", err)
		return
	}

	var req requests.UpdateProductRequest
	if !utils.BindAndValidate(ctx, &req) {
		return
	}

	product, err := c.productService.UpdateProduct(uint(id), &req)
	if err != nil {
		if err.Error() == "product not found" {
			utils.SendErrorResponse(ctx, http.StatusNotFound, "Product not found", err)
			return
		}
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to update product", err)
		return
	}

	utils.SendSuccessResponse(ctx, http.StatusOK, "Product updated successfully", product)
}

// DeleteProduct godoc
// @Summary Delete a product
// @Description Delete a product by its ID
// @Tags products
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /products/{id} [delete]
func (c *ProductController) DeleteProduct(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusBadRequest, "Invalid product ID", err)
		return
	}

	err = c.productService.DeleteProduct(uint(id))
	if err != nil {
		if err.Error() == "product not found" {
			utils.SendErrorResponse(ctx, http.StatusNotFound, "Product not found", err)
			return
		}
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to delete product", err)
		return
	}

	utils.SendSuccessResponse(ctx, http.StatusOK, "Product deleted successfully", nil)
}
