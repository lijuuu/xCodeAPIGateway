package configs

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// Config holds application configuration
type Config struct {
	// Environment
	Environment  string
	JWTSecretKey string
	// Microservices
	APIGATEWAYPORT     string
	UserGRPCPort       string
	CompilerGRPCPort   string
	ProblemGRPCPort    string
	NATSURL            string
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	FrontendURL string
}

// LoadConfig loads configuration from environment variables with defaults
func LoadConfig() Config {
	// Load .env file if present
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found, using system environment variables or defaults ",err)
	}

	return Config{
		Environment:        getEnv("ENVIRONMENT", "development"),
		JWTSecretKey:       getEnv("JWTSECRETKEY", "secretLeetcode"),
		APIGATEWAYPORT:     getEnv("APIGATEWAYPORT", "7000"),
		UserGRPCPort:       getEnv("USERGRPCPORT", "50051"),
		CompilerGRPCPort:   getEnv("COMPILERGRPCPORT", "50053"),
		ProblemGRPCPort:    getEnv("PROBLEMGRPCPORT", "50055"),
		NATSURL:            getEnv("NATSURL", "nats://localhost:4222"),
		GoogleClientID:     getEnv("GOOGLECLIENTID", ""),
		GoogleClientSecret: getEnv("GOOGLECLIENTSECRET", ""),
		GoogleRedirectURL:  getEnv("GOOGLEREDIRECTURL", ""),

		FrontendURL: getEnv("FRONTENDURL", "http://localhost:8080"),
	}
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	log.Printf("Environment variable %s not set, using default: %s", key, defaultValue)
	return defaultValue
}
