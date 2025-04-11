package router

import (
	"log"
	"xcode/clients"
	"xcode/configs"
	"xcode/controller"
	"xcode/middleware"
	"xcode/natsclient"

	"github.com/gin-gonic/gin"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	ProblemsService "github.com/lijuuu/GlobalProtoXcode/ProblemsService"
)

// SetupRoutes initializes all API routes with middleware and controllers under /api/v1/
func SetupRoutes(router *gin.Engine, clients *clients.ClientConnections, jwtSecret string) {

	// Initialize gRPC client and controllers
	userClient := AuthUserAdminService.NewAuthUserAdminServiceClient(clients.ConnUser)
	userController := controller.NewUserController(userClient)

	natsClient, err := natsclient.NewNatsClient(configs.LoadConfig().NATSURL)
	if err != nil {
		log.Fatalf("Failed to create NATS client: %v", err)
	}
	compilerController := controller.NewCompilerController(natsClient)

	problemClient := ProblemsService.NewProblemsServiceClient(clients.ConnProblem)
	problemController := controller.NewProblemController(problemClient)

	// Base API group with version prefix
	apiV1 := router.Group("/api/v1")

	// Organize routes into logical groups
	setupPublicAuthRoutes(apiV1, userController)
	setupProtectedUserRoutes(apiV1, userController, jwtSecret)
	setupAdminRoutes(apiV1, userController, jwtSecret)
	setUPCompilerRoutes(apiV1, compilerController)
	setUPProblemRoutes(apiV1, problemController)
}

// setupPublicAuthRoutes defines endpoints for authentication (no JWT required)
func setupPublicAuthRoutes(apiV1 *gin.RouterGroup, userController *controller.UserController) {
	auth := apiV1.Group("/auth")
	{
		auth.POST("/register", userController.RegisterUserHandler)
		auth.POST("/login", userController.LoginUserHandler)
		// auth.GET("/login/google", userController)
		auth.GET("/google/login", userController.GoogleLoginInitiate)
		auth.GET("/google/callback", userController.GoogleLoginCallback)

		auth.POST("/token/refresh", userController.TokenRefreshHandler)
		auth.GET("/verify", userController.VerifyUserHandler)                     // ?email=user@example.com&token=123456
		auth.GET("/verify/resend", userController.ResendEmailVerificationHandler) // ?email=user@example.com
		auth.POST("/password/forgot", userController.ForgotPasswordHandler)       // ?email=user@example.com
		// Updated to use JSON body for sensitive data instead of query parameters
		auth.POST("/password/reset", userController.FinishForgotPasswordHandler) // JSON body: { "email", "token", "newPassword", "confirmPassword" }

		auth.GET("/2fa/status", userController.GetTwoFactorAuthStatusHandler) //http://localhost:7000/api/v1/auth/2fa/status?email=user@example.com
	}
}

// setupProtectedUserRoutes defines endpoints for authenticated users (USER role)
func setupProtectedUserRoutes(apiV1 *gin.RouterGroup, userController *controller.UserController, jwtSecret string) {

	users := apiV1.Group("/users")
	users.GET("/public/profile", userController.GetUserProfilePublicHandler)

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
			follow.POST("", userController.FollowUserHandler)            // ?followeeID=uuid (followerID from JWT)
			follow.DELETE("", userController.UnfollowUserHandler)        // ?followeeID=uuid (followerID from JWT)
			follow.GET("/following", userController.GetFollowingHandler) // ?userID=uuid (optional)&pageToken=abc&limit=10
			follow.GET("/followers", userController.GetFollowersHandler) // ?userID=uuid (optional)&pageToken=abc&limit=10
		}

		// Security settings
		security := users.Group("/security")
		{
			security.POST("/password/change", userController.ChangePasswordHandler)
		// 	type ChangePasswordRequest struct {
		// 		// UserID          string `json:"userID"` from context no need in body
		// 		OldPassword     string `json:"oldPassword"`
		// 		NewPassword     string `json:"newPassword"`
		// 		ConfirmPassword string `json:"confirmPassword"`
		// }

			security.POST("/2fa/setup", userController.SetUpTwoFactorAuthHandler)     //http://localhost:7000/api/v1/users/security/2fa/setup json:"password"
			security.POST("/2fa/verify",userController.VerifyTwoFactorAuth) //json body :otp
			security.DELETE("/2fa/setup", userController.DisableTwoFactorAuthHandler) //http://localhost:7000/api/v1/users/security/2fa/setup json:"password,otp"
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
			adminUsers.GET("", userController.GetAllUsersHandler)                        // ?pageToken=abc&limit=10&roleFilter=USER&statusFilter=active
			adminUsers.POST("", userController.CreateUserAdminHandler)                   // JSON body
			adminUsers.PUT("/update", userController.UpdateUserAdminHandler)             // JSON body: { "userID", ... }
			adminUsers.DELETE("/soft-delete", userController.SoftDeleteUserAdminHandler) // JSON body: { "userID" }
			adminUsers.POST("/verify", userController.VerifyAdminUserHandler)            // JSON body: { "userID" }
			adminUsers.POST("/unverify", userController.UnverifyUserHandler)             // JSON body: { "userID" }
			adminUsers.POST("/ban", userController.BanUserHandler)                       // JSON body: { "userID", "banType", "banReason", "banExpiry" }
			adminUsers.POST("/unban", userController.UnbanUserHandler)                   // JSON body: { "userID" }
			adminUsers.GET("/ban-history", userController.BanHistoryHandler)             // ?userID=uuid
		}
	}
}

func setUPCompilerRoutes(apiV1 *gin.RouterGroup, compilerController *controller.CompilerController) {
	compiler := apiV1.Group("")
	{
		compiler.POST("/compile", compilerController.CompileCodeHandler)
	}
}

func setUPProblemRoutes(apiV1 *gin.RouterGroup, problemController *controller.ProblemController) {
	problem := apiV1.Group("problems")
	{
		problem.POST("/", problemController.CreateProblemHandler)                    // JSON body: { "title", "description", "tags", "difficulty" }
		problem.PUT("/", problemController.UpdateProblemHandler)                     // JSON body: { "problem_id", "title", "description", "tags", "difficulty" }
		problem.DELETE("/", problemController.DeleteProblemHandler)                  // ?problem_id=uuid
		problem.GET("/", problemController.GetProblemHandler)                        // ?problem_id=uuid
		problem.GET("/list", problemController.ListProblemsHandler)                  // ?page=1&page_size=10&tags=tag1,tag2&difficulty=easy&search_query=text
		problem.POST("/testcases", problemController.AddTestCasesHandler)            // JSON body: { "problem_id", "testcases": { "run", "submit" } }
		problem.DELETE("/testcases/single", problemController.DeleteTestCaseHandler) // JSON body: { "problem_id", "testcase_id", "is_run_testcase" }
		problem.POST("/language", problemController.AddLanguageSupportHandler)       // JSON body: { "problem_id", "language", "validation_code" }
		problem.PUT("/language", problemController.UpdateLanguageSupportHandler)     // JSON body: { "problem_id", "language", "validation_code" }
		problem.DELETE("/language", problemController.RemoveLanguageSupportHandler)  // JSON body: { "problem_id", "language" }
		problem.GET("/validate", problemController.FullValidationByProblemIDHandler) // ?problem_id=uuid
		problem.GET("/languages", problemController.GetLanguageSupportsHandler)      // ?problem_id=uuid
		problem.POST("/execute", problemController.RunUserCodeProblemHandler)        // JSON body: { "problem_id", "user_code", "langauge", "is_run_testcase" }
		problem.GET("/metadata", problemController.GetProblemByIDSlugHandler)        // ?problem_id=uuid || slug=text
		problem.GET("/metadata/list", problemController.GetProblemByIDListHandler)   // ?page=1&page_size=10&tags=tag1,tag2&difficulty=easy&search_query=text

		problem.GET("submission/history",problemController.GetSubmissionHistoryOptionalProblemId) // type = recent show limit 10 and offset, or problemid . show limit 10 
		//http://localhost:7000/api/v1/problems/submission/history
		// UserID    string `json:"userID"`
    // ProblemID string `json:"problemID,omitempty"`
    // Page      int    `json:"page"`
    // Limit     int    `json:"limit"`
		problem.GET("/stats",problemController.GetProblemStatistics)  //query params userID=?
	}
}
