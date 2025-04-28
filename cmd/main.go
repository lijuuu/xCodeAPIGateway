package main

import (
	"net/http"
	"os"
	"xcode/clients"

	config "xcode/configs"
	zap_betterstack "xcode/logger"
	cache "xcode/ristretto"
	router "xcode/route"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/time/rate"
)

func newZapLogger(environment string) (*zap.Logger, error) {
	// Configure encoder
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	// Set log level based on environment
	logLevel := zapcore.InfoLevel
	if environment == "development" {
		logLevel = zapcore.DebugLevel // Include DEBUG in development
	}

	// Create core
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.Lock(os.Stdout),
		logLevel,
	)

	// Add caller and stacktrace for errors
	return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel)), nil
}

func main() {
	// Load environment variables
	config := config.LoadConfig()
	
	// Initialize zap logger
	logger, err := newZapLogger(config.Environment)
	if err != nil {
		panic("Failed to initialize zap logger: " + err.Error())
	}
	defer logger.Sync()

	// Initialize gRPC clients
	Client, err := clients.InitClients(&config)
	if err != nil {
		logger.Error("Failed to initialize gRPC clients", zap.Error(err))
		os.Exit(1)
	}
	defer Client.Close()

	// Create a new Gin router
	ginRouter := gin.Default()

	// Apply BetterStack logging middleware
	ginRouter.Use(zap_betterstack.BetterStackLoggingMiddleware(config.BetterStackSourceToken, config.Environment,config.BetterStackUploadURL, logger))

	// Apply rate limiting middleware
	limiter := rate.NewLimiter(1, 10)
	ginRouter.Use(func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
			c.Abort()
			return
		}
		c.Next()
	})

	cacheInstance, err := cache.NewCache()
	if err != nil {
		logger.Error("Failed to initialize cache", zap.Error(err))
		os.Exit(1)
	}

	// Middleware to set the cache in the context for all routes
	ginRouter.Use(func(c *gin.Context) {
		c.Set("cacheInstance", cacheInstance)
		c.Next()
	})

	ginRouter.GET("test-cache", func(c *gin.Context) {
		_, exists := c.Get("cacheInstance")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Cache instance not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Cache instance found"})
	})

	// CORS middleware
	ginRouter.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "Access-Control-Allow-Origin"},
	}))

	// Setup all routes
	router.SetupRoutes(ginRouter, Client, config.JWTSecretKey)

	// Start the HTTP server (API Gateway)
	logger.Info("API Gateway is running", zap.String("port", config.APIGATEWAYPORT))
	if err := ginRouter.Run(":" + config.APIGATEWAYPORT); err != nil {
		logger.Error("Failed to start HTTP server", zap.Error(err))
		os.Exit(1)
	}
}