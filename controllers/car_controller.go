package controllers

import (
	"net/http"
	"strconv"

	requests "api-rentcar/requests"
	"api-rentcar/responses"
	"api-rentcar/services"
	"api-rentcar/utils"

	"github.com/gin-gonic/gin"
)

// CarController handles car related requests
type CarController struct {
	carService services.CarServiceInterface
}

// NewCarController creates a new car controller
func NewCarController(carService services.CarServiceInterface) *CarController {
	return &CarController{
		carService: carService,
	}
}

// CreateCar godoc
// @Summary Create a new car
// @Description Create a new car with the provided information
// @Tags cars
// @Accept json
// @Produce json
// @Param car body requests.CreateCarRequest true "Car creation request"
// @Success 201 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /cars [post]
func (c *CarController) CreateCar(ctx *gin.Context) {
	var req requests.CreateCarRequest
	if !utils.BindAndValidate(ctx, &req) {
		return
	}

	_, err := c.carService.CreateCar(&req)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to create car", err)
		return
	}

	response := utils.SuccessResponse{
		Success: true,
		Message: "Car created successfully",
	}
	ctx.JSON(http.StatusCreated, response)
}

// GetCars godoc
// @Summary Get all cars
// @Description Get a list of cars with optional pagination and filtering
// @Tags cars
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Param available query bool false "Filter by availability"
// @Success 200 {object} responses.CarsListResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /cars [get]
func (c *CarController) GetCars(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(ctx.DefaultQuery("limit", "10"))
	available := ctx.Query("available")

	var availableBool *bool
	if available != "" {
		switch available {
		case "true":
			availableBool = &[]bool{true}[0]
		case "false":
			availableBool = &[]bool{false}[0]
		}
	}

	cars, total, err := c.carService.GetCars(page, limit, availableBool)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to fetch cars", err)
		return
	}

	response := responses.ToCarsListResponse(cars, total, page, limit)
	ctx.JSON(http.StatusOK, response)
}

// GetCar godoc
// @Summary Get a car by ID
// @Description Get a single car by its ID
// @Tags cars
// @Accept json
// @Produce json
// @Param id path int true "Car ID"
// @Success 200 {object} responses.CarResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /cars/{id} [get]
func (c *CarController) GetCar(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusBadRequest, "Invalid car ID", err)
		return
	}

	car, err := c.carService.GetCarByID(uint(id))
	if err != nil {
		if err.Error() == "car not found" {
			utils.SendErrorResponse(ctx, http.StatusNotFound, "Car not found", err)
			return
		}
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to fetch car", err)
		return
	}

	response := responses.ToCarResponse(car)
	ctx.JSON(http.StatusOK, response)
}

// UpdateCar godoc
// @Summary Update a car
// @Description Update an existing car with the provided information
// @Tags cars
// @Accept json
// @Produce json
// @Param id path int true "Car ID"
// @Param car body requests.UpdateCarRequest true "Car update request"
// @Success 200 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /cars/{id} [put]
func (c *CarController) UpdateCar(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusBadRequest, "Invalid car ID", err)
		return
	}

	var req requests.UpdateCarRequest
	if !utils.BindAndValidate(ctx, &req) {
		return
	}

	_, err = c.carService.UpdateCar(uint(id), &req)
	if err != nil {
		if err.Error() == "car not found" {
			utils.SendErrorResponse(ctx, http.StatusNotFound, "Car not found", err)
			return
		}
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to update car", err)
		return
	}

	response := utils.SuccessResponse{
		Success: true,
		Message: "Car updated successfully",
	}
	ctx.JSON(http.StatusOK, response)
}

// DeleteCar godoc
// @Summary Delete a car
// @Description Delete a car by its ID
// @Tags cars
// @Accept json
// @Produce json
// @Param id path int true "Car ID"
// @Success 200 {object} utils.SuccessResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Failure 500 {object} utils.ErrorResponse
// @Router /cars/{id} [delete]
func (c *CarController) DeleteCar(ctx *gin.Context) {
	idParam := ctx.Param("id")
	id, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		utils.SendErrorResponse(ctx, http.StatusBadRequest, "Invalid car ID", err)
		return
	}

	err = c.carService.DeleteCar(uint(id))
	if err != nil {
		if err.Error() == "car not found" {
			utils.SendErrorResponse(ctx, http.StatusNotFound, "Car not found", err)
			return
		}
		utils.SendErrorResponse(ctx, http.StatusInternalServerError, "Failed to delete car", err)
		return
	}

	response := utils.SuccessResponse{
		Success: true,
		Message: "Car deleted successfully",
	}
	ctx.JSON(http.StatusOK, response)
}
