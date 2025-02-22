package router

import (
    "xcode/clients"
    "xcode/controller"
    "xcode/middleware"

    "github.com/gin-gonic/gin"
    user "github.com/lijuuu/GlobalProtoXcode/UserService"
)

// InitializeServiceRoutes sets up all service routes with appropriate middleware
func InitializeServiceRoutes(router *gin.Engine, clients *clients.ClientConnections) {
    userClient := user.NewUserServiceClient(clients.ConnUser)
    userController := controller.NewUserController(userClient)

    // Setup route groups
    setupPublicRoutes(router, userController)
    setupProtectedRoutes(router, userController)
    setupAdminRoutes(router, userController)
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
func setupProtectedRoutes(router *gin.Engine, userController *controller.UserController) {
    api := router.Group("/api/users")
    api.Use(
        middleware.JWTAuthMiddleware(),
        middleware.UserAuthMiddleware(),
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
func setupAdminRoutes(router *gin.Engine, userController *controller.UserController) {
    admin := router.Group("/admin/users")
    admin.Use(
        middleware.JWTAuthMiddleware(),
        // middleware.AdminAuthMiddleware(),
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
        admin.GET("", userController.GetAllUsersHandler)
        admin.GET("/:userID/following", userController.GetFollowingHandler)
        admin.GET("/:userID/followers", userController.GetFollowersHandler)
    }
}