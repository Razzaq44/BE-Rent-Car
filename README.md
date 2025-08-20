# Go RESTfulAPI Management

A RESTful API management built with Go, Gin, and GORM.

## Features

- **CRUD Operations**: Complete Create, Read, Update, Delete operations for products
- **Database Integration**: SQLite database with GORM ORM
- **API Documentation**: Swagger/OpenAPI documentation
- **Middleware**: Logging, CORS, Rate limiting, Security headers
- **Validation**: Request validation with custom error messages
- **Testing**: Unit tests for controllers
- **Environment Configuration**: Configurable via environment variables

## Tech Stack

- **Go 1.21+**
- **Gin Web Framework**
- **GORM** (with SQLite driver)
- **Swagger** (API documentation)
- **Testify** (testing framework)

## Project Structure

```
API-RentCar/
├── cmd/api/           # Application entry point
├── config/            # Configuration management
├── controllers/       # HTTP handlers
├── docs/              # Swagger documentation
├── middleware/        # HTTP middleware
├── models/            # Database models
├── routes/            # Route definitions
├── tests/             # Unit tests
├── utils/             # Utility functions
├── .env               # Environment variables
└── go.mod             # Go module file
```

## Getting Started

### Prerequisites

- Go 1.21 or higher
- Git

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd API-RentCar
```

2. Install dependencies:
```bash
go mod tidy
```

3. Copy and configure environment variables:
```bash
cp .env.example .env
```

4. Run the application:
```bash
go run cmd/api/main.go
```

5. Access the API documentation:
```
http://localhost:8080/swagger/index.html
```

6. Generate Swagger documentation:
```bash
go run github.com/swaggo/swag/cmd/swag@latest init -g cmd/api/main.go -o docs --parseDependency --parseInternal
```

7. Access points:
   - API endpoint: `http://localhost:8080`
   - API documentation: `http://localhost:8080/swagger/index.html`

## API Endpoints

### Health Check
- `GET /health` - Health check endpoint

### Documentation
- `GET /swagger/*` - Swagger UI documentation

## API Documentation

Once the server is running, you can access the interactive API documentation at:
`http://localhost:8080/swagger/index.html`

## Testing

Run the test suite:
```bash
go test ./tests/...
```

Run tests with coverage:
```bash
go test -cover ./tests/...
```

## Development

### Code Generation
This project includes a code generator to scaffold new modules (controllers, services, repositories, models, requests, responses).
To use the generator, run:
```bash
go run cmd/generator/main.go
```
This command will prompt you to select the module type (e.g., `controller`, `service`, `model`, `request`, `response`, `repository`) and provide the necessary names. The generated files will be placed in their respective subdirectories within `cmd/generator/`.

For example, if you generate a `Car` module, the following files might be created:
- `cmd/generator/controller/car_generator.go`
- `cmd/generator/service/car_generator.go`
- `cmd/generator/repository/car_generator.go`
- `cmd/generator/model/car_generator.go`
- `cmd/generator/request/car_generator.go`
- `cmd/generator/response/car_generator.go`

Follow the prompts to select the module type and provide the necessary names.

### Adding New Endpoints

1. Define the model in `models/`
2. Create controller in `controllers/`
3. Add routes in `routes/routes.go`
4. Add Swagger annotations
5. Write tests in `tests/`

### Database Migrations

The application uses GORM's auto-migration feature. Models are automatically migrated on startup.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.