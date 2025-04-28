package main

import (
	"net/http"

	"xcode/clients"
	"xcode/configs"
	logger "xcode/logger"
	ristretto "xcode/ristretto"
	route "xcode/route"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func main() {
	// load configs
	cfg := configs.LoadConfig()

	// init zap logger
	log, _ := zap.NewDevelopment()
	defer log.Sync()

	// init gRPC clients
	client, err := clients.InitClients(&cfg)
	if err != nil {
		log.Fatal("init gRPC clients failed", zap.Error(err))
	}
	defer client.Close()

	// gin router
	r := gin.Default()

	// betterstack logging middleware
	r.Use(logger.BetterStackLoggingMiddleware(cfg.BetterStackSourceToken, cfg.Environment, cfg.BetterStackUploadURL, log))

	// rate limiting middleware
	limiter := rate.NewLimiter(1, 10)
	r.Use(func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
			c.Abort()
			return
		}
		c.Next()
	})

	// cache setup
	cacheInstance, err := ristretto.NewCache()
	if err != nil {
		log.Fatal("cache init failed", zap.Error(err))
	}
	r.Use(func(c *gin.Context) {
		c.Set("cacheInstance", cacheInstance)
		c.Next()
	})

	r.GET("/test-cache", func(c *gin.Context) {
		if _, exists := c.Get("cacheInstance"); !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "cache instance not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "cache instance ok"})
	})

	// cors setup
	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Content-Type", "Authorization", "X-CSRF-Token", "Access-Control-Allow-Origin"},
	}))

	// routes
	route.SetupRoutes(r, client, cfg.JWTSecretKey)

	// start server
	port := cfg.APIGATEWAYPORT
	log.Info("API Gateway running", zap.String("port", port))
	if err := r.Run(":" + port); err != nil {
		log.Fatal("server failed", zap.Error(err))
	}
}
