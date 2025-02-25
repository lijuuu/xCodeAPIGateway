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
	adminController := controller.NewAdminController()

	// Base API group with version prefix
	apiV1 := router.Group("/api/v1")

	// Organize routes into logical groups
	setupPublicAuthRoutes(apiV1, userController)
	setupProtectedUserRoutes(apiV1, userController, jwtSecret)
	setupAdminRoutes(apiV1, userController, adminController, jwtSecret)
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
			profile.GET("/all", userController.GetAllUsersHandler)
			profile.PUT("/update", userController.UpdateProfileHandler)
			profile.PATCH("/image", userController.UpdateProfileImageHandler)
		}

		// Social follow system
		follow := users.Group("/follow")
		{
			follow.POST("", userController.FollowUserHandler)      // ?userID=uuid
			follow.DELETE("", userController.UnfollowUserHandler)  // ?userID=uuid
			follow.GET("/following", userController.GetFollowingHandler) // ?userID=uuid (optional)
			follow.GET("/followers", userController.GetFollowersHandler) // ?userID=uuid (optional)
		}

		// Security settings
		security := users.Group("/security")
		{
			security.POST("/password/change", userController.ChangePasswordHandler)
			security.POST("/2fa", userController.SetTwoFactorAuthHandler)
		}

		users.POST("/logout", userController.LogoutUserHandler)
	}
}

// setupAdminRoutes defines endpoints for admin operations (ADMIN role)
func setupAdminRoutes(apiV1 *gin.RouterGroup, userController *controller.UserController, adminController *controller.AdminController, jwtSecret string) {
	adminRoot := apiV1.Group("/admin")
	{
		adminRoot.POST("/login", adminController.LoginAdminHandler)

		adminUsers := adminRoot.Group("/users")
		adminUsers.Use(
			middleware.JWTAuthMiddleware(jwtSecret),
			middleware.RoleAuthMiddleware(middleware.RoleAdmin),
		)
		{
			adminUsers.GET("", userController.GetAllUsersHandler) // ?page=1&limit=10&roleFilter=USER&statusFilter=active
			adminUsers.POST("", userController.CreateUserAdminHandler)
			adminUsers.PUT("/update", userController.UpdateUserAdminHandler) // ?userID=uuid
			adminUsers.DELETE("/soft-delete", userController.SoftDeleteUserAdminHandler) // ?userID=uuid
			adminUsers.POST("/verify", userController.VerifyAdminUserHandler) // ?userID=uuid
			adminUsers.POST("/unverify", userController.UnverifyUserHandler) // ?userID=uuid
			adminUsers.POST("/block", userController.BlockUserHandler) // ?userID=uuid
			adminUsers.POST("/unblock", userController.UnblockUserHandler) // ?userID=uuid
		}
	}
}