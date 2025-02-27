package router

import (
	"xcode/clients"
	"xcode/controller"
	"xcode/middleware"

	"github.com/gin-gonic/gin"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
)

// SetupRoutes initializes all API routes with middleware and controllers under /api/v1/
func SetupRoutes(router *gin.Engine, clients *clients.ClientConnections, jwtSecret string) {
	// Initialize gRPC client and controllers
	userClient := AuthUserAdminService.NewAuthUserAdminServiceClient(clients.ConnUser)
	userController := controller.NewUserController(userClient)
	// adminController := controller.NewAdminController()

	// Base API group with version prefix
	apiV1 := router.Group("/api/v1")

	// Organize routes into logical groups
	setupPublicAuthRoutes(apiV1, userController)
	setupProtectedUserRoutes(apiV1, userController, jwtSecret)
	setupAdminRoutes(apiV1, userController, jwtSecret)
}

// setupPublicAuthRoutes defines endpoints for authentication (no JWT required)
func setupPublicAuthRoutes(apiV1 *gin.RouterGroup, userController *controller.UserController) {
	auth := apiV1.Group("/auth")
	{
		auth.POST("/register", userController.RegisterUserHandler)
		auth.POST("/login", userController.LoginUserHandler)
		auth.POST("/token/refresh", userController.TokenRefreshHandler)
		auth.GET("/verify", userController.VerifyUserHandler)       // ?userID=uuid&token=123456
		auth.GET("/otp/resend", userController.ResendOTPHandler)    // ?userID=uuid
		auth.GET("/password/forgot", userController.ForgotPasswordHandler) // ?email=user@example.com
		// Updated to use JSON body for sensitive data instead of query parameters
		auth.POST("/password/reset", userController.FinishForgotPasswordHandler) // JSON body: { "userID", "token", "newPassword", "confirmPassword" }
	}
}

// setupProtectedUserRoutes defines endpoints for authenticated users (USER role)
func setupProtectedUserRoutes(apiV1 *gin.RouterGroup, userController *controller.UserController, jwtSecret string) {
	users := apiV1.Group("/users")
	users.Use(
		middleware.JWTAuthMiddleware(jwtSecret),
		middleware.RoleAuthMiddleware(middleware.RoleUser),
		middleware.UserBanCheckMiddleware(userController.GetUserClient()),
	)
	{
		// User profile management
		profile := users.Group("/profile")
		{
			profile.GET("", userController.GetUserProfileHandler)
			profile.PUT("/update", userController.UpdateProfileHandler)
			profile.PATCH("/image", userController.UpdateProfileImageHandler)
			// Optionally allow users to view their own ban history
			profile.GET("/ban-history", userController.BanHistoryHandler) // No userID needed (uses authenticated user)
		}

		// Social follow system
		follow := users.Group("/follow")
		{
			follow.POST("", userController.FollowUserHandler)      // ?followeeID=uuid (followerID from JWT)
			follow.DELETE("", userController.UnfollowUserHandler)  // ?followeeID=uuid (followerID from JWT)
			follow.GET("/following", userController.GetFollowingHandler) // ?userID=uuid (optional)&pageToken=abc&limit=10
			follow.GET("/followers", userController.GetFollowersHandler) // ?userID=uuid (optional)&pageToken=abc&limit=10
		}

		// Security settings
		security := users.Group("/security")
		{
			security.POST("/password/change", userController.ChangePasswordHandler)
			security.POST("/2fa", userController.SetTwoFactorAuthHandler)
		}

		// User search functionality
		users.GET("/search", userController.SearchUsersHandler) // ?query=abc&pageToken=def&limit=10

		users.POST("/logout", userController.LogoutUserHandler)
	}
}

// setupAdminRoutes defines endpoints for admin operations (ADMIN role)
func setupAdminRoutes(apiV1 *gin.RouterGroup, userController *controller.UserController, jwtSecret string) {
	adminRoot := apiV1.Group("/admin")
	{
		// Corrected to use userController since LoginAdmin is part of AuthUserAdminService
		adminRoot.POST("/login", userController.LoginAdminHandler)

		adminUsers := adminRoot.Group("/users")
		adminUsers.Use(
			middleware.JWTAuthMiddleware(jwtSecret),
			middleware.RoleAuthMiddleware(middleware.RoleAdmin),
		)
		{
			adminUsers.GET("", userController.GetAllUsersHandler) // ?pageToken=abc&limit=10&roleFilter=USER&statusFilter=active
			adminUsers.POST("", userController.CreateUserAdminHandler) // JSON body
			adminUsers.PUT("/update", userController.UpdateUserAdminHandler) // JSON body: { "userID", ... }
			adminUsers.DELETE("/soft-delete", userController.SoftDeleteUserAdminHandler) // JSON body: { "userID" }
			adminUsers.POST("/verify", userController.VerifyAdminUserHandler) // JSON body: { "userID" }
			adminUsers.POST("/unverify", userController.UnverifyUserHandler) // JSON body: { "userID" }
			adminUsers.POST("/ban", userController.BanUserHandler) // JSON body: { "userID", "banType", "banReason", "banExpiry" }
			adminUsers.POST("/unban", userController.UnbanUserHandler) // JSON body: { "userID" }
			adminUsers.GET("/ban-history", userController.BanHistoryHandler) // ?userID=uuid
		}
	}
}