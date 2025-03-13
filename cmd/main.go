package main

import (
	"log"
	"net/http"

	"xcode/clients"
	config "xcode/configs"
	router "xcode/route"

	// "xcode/utils"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

func main() {
	// Load environment variables
	config := config.LoadConfig()

	// Initialize gRPC clients
	Client, err := clients.InitClients(&config)
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer Client.Close()

	// Create a new Gin router
	ginRouter := gin.Default()

	// Apply rate limiting middleware using the rate package
	limiter := rate.NewLimiter(1, 10)
	ginRouter.Use(func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
			c.Abort()
			return
		}
		c.Next()
	})

	// ginRouter.Use(cors.Default())
	ginRouter.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization", "Access-Control-Allow-Origin"},
	}))

	// Setup all routes
	router.SetupRoutes(ginRouter, Client, config.JWTSecretKey)

	// Start the HTTP server (API Gateway)
	log.Printf("API Gateway is running on port %s", config.APIGATEWAYPORT)
	if err := ginRouter.Run(":" + config.APIGATEWAYPORT); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}
