package main

import (
	"log"

	"xcode/clients"
	config "xcode/configs"
	router "xcode/route"

	// "github.com/gin-contrib/cors"

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
	limiter := rate.NewLimiter(1, 3)
	ginRouter.Use(func(c *gin.Context) {
		if !limiter.Allow() {
			c.AbortWithStatus(429)
		}
		c.Next()
	})

	// ginRouter.Use(cors.New(cors.Config{
	// 	AllowOrigins: []string{"http://localhost:7000"},
	// 	AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
	// 	AllowHeaders: []string{"Authorization", "Content-Type"},
	// }))

	// Setup all routes
	router.InitializeServiceRoutes(ginRouter, Client)

	// Start the HTTP server (API Gateway)
	log.Printf("API Gateway is running on port %s", config.APIGATEWAYPORT)
	if err := ginRouter.Run(":" + config.APIGATEWAYPORT); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}
