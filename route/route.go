package router

import (
	"xcode/clients"
	"xcode/controller"
	"xcode/middleware"

	"github.com/gin-gonic/gin"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
)

// InitializeServiceRoutes sets up all service routes with appropriate middleware
func InitializeServiceRoutes(router *gin.Engine, clients *clients.ClientConnections, jwtSecret string) {
	userClient := AuthUserAdminService.NewAuthUserAdminServiceClient(clients.ConnUser)
	userController := controller.NewUserController(userClient)
	adminController := controller.NewAdminController()

	// Setup route groups
	setupPublicRoutes(router, userController)
	setupProtectedRoutes(router, userController, jwtSecret)
	setupAdminRoutes(router, userController, adminController, jwtSecret)
}

// setupPublicRoutes handles authentication-related endpoints
func setupPublicRoutes(router *gin.Engine, userController *controller.UserController) {
	auth := router.Group("/auth")
	{
		auth.POST("/register", userController.RegisterUserHandler)
		auth.POST("/login", userController.LoginUserHandler)
		auth.POST("/token/refresh", userController.TokenRefreshHandler)
		auth.POST("/verify", userController.VerifyUserHandler)
		auth.POST("/otp/resend", userController.ResendOTPHandler)
		auth.POST("/password/forgot", userController.ForgotPasswordHandler)
	}
}

// setupProtectedRoutes handles authenticated user endpoints
func setupProtectedRoutes(router *gin.Engine, userController *controller.UserController, jwtSecret string) {
	api := router.Group("/api/users")
	api.Use(
		middleware.JWTAuthMiddleware(jwtSecret),
		middleware.RoleAuthMiddleware(middleware.RoleUser), // Only USER role allowed
		middleware.UserBanCheckMiddleware(userController.GetUserClient()),
	)
	{
		// Profile management
		profile := api.Group("/profile")
		{
			profile.GET("", userController.GetUserProfileHandler)
			profile.PUT("", userController.UpdateProfileHandler)
			profile.PUT("/image", userController.UpdateProfileImageHandler)
		}

		// Follow system
		follow := api.Group("/follow")
		{
			follow.POST("/:userID", userController.FollowUserHandler)
			follow.DELETE("/:userID", userController.UnfollowUserHandler)
			follow.GET("/following", userController.GetFollowingHandler)
			follow.GET("/followers", userController.GetFollowersHandler)
		}

		// Security settings
		security := api.Group("/security")
		{
			security.POST("/password/change", userController.ChangePasswordHandler)
			security.POST("/2fa", userController.SetTwoFactorAuthHandler)
		}

		// Session management
		api.POST("/logout", userController.LogoutUserHandler)
	}
}

// setupAdminRoutes handles admin-only endpoints
func setupAdminRoutes(router *gin.Engine, userController *controller.UserController, adminController *controller.AdminController, jwtSecret string) {
	api := router.Group("/api/admin")
	api.POST("/login", adminController.LoginAdminHandler)
	admin := api.Group("/users")
	admin.Use(
		middleware.JWTAuthMiddleware(jwtSecret),
		middleware.RoleAuthMiddleware(middleware.RoleAdmin),
	)
	{
		// User management
		admin.GET("/", userController.GetAllUsersHandler)
		admin.POST("", userController.CreateUserAdminHandler)
		admin.PUT("/:userID", userController.UpdateUserAdminHandler)
		admin.DELETE("/:userID/soft", userController.SoftDeleteUserAdminHandler)

		// Verification
		admin.POST("/:userID/verify", userController.VerifyAdminUserHandler)
		admin.POST("/:userID/unverify", userController.UnverifyUserHandler)

		// Blocking
		admin.POST("/:userID/block", userController.BlockUserHandler)
		admin.POST("/:userID/unblock", userController.UnblockUserHandler)

		// Listings
		admin.GET("/:userID/following", userController.GetFollowingHandler)
		admin.GET("/:userID/followers", userController.GetFollowersHandler)
	}
}
