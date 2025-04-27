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
func SetupRoutes(Router *gin.Engine, Clients *clients.ClientConnections, JWTSecret string) {
	// Initialize gRPC clients and controllers
	UserClient := AuthUserAdminService.NewAuthUserAdminServiceClient(Clients.ConnUser)
	UserController := controller.NewUserController(UserClient)

	NatsClient, err := natsclient.NewNatsClient(configs.LoadConfig().NATSURL)
	if err != nil {
		log.Fatalf("Failed to create NATS client: %v", err)
	}
	CompilerController := controller.NewCompilerController(NatsClient)

	ProblemClient := ProblemsService.NewProblemsServiceClient(Clients.ConnProblem)
	ProblemController := controller.NewProblemController(ProblemClient, UserClient)

	// Base API group with version prefix
	ApiV1 := Router.Group("/api/v1")

	// Organize routes into logical groups
	SetUpPublicAuthRoutes(ApiV1, UserController)
	SetUpProtectedUserRoutes(ApiV1, UserController, JWTSecret)
	SetUpAdminRoutes(ApiV1, UserController, JWTSecret)
	SetUpCompilerRoutes(ApiV1, CompilerController)
	SetUpProblemRoutes(ApiV1, ProblemController, JWTSecret, UserController)
}

// SetUpPublicAuthRoutes defines public authentication endpoints (no JWT required)
func SetUpPublicAuthRoutes(ApiV1 *gin.RouterGroup, UserController *controller.UserController) {
	Auth := ApiV1.Group("/auth")
	{
		// detail: "Registers a new user with email and password"
		// type: POST
		// url: BaseURL/api/v1/auth/register
		// requesttype: JSON
		// request structure: {"first_name": "John", "last_name": "Doe", "email": "john@example.com", "password": "password123", "confirm_password": "password123"}
		// response structure: {"success": true, "status": 200, "payload": {"user_id": "uuid", "access_token": "jwt_token", "refresh_token": "jwt_token", "expires_in": 3600, "user_profile": {"user_id": "uuid", "username": "johndoe", "first_name": "John", "last_name": "Doe", "email": "john@example.com", "country": "US", "bio": "", "primary_language_id": "en", "mute_notifications": false, "socials": {}, "created_at": "2025-04-22T12:00:00Z", "updated_at": "2025-04-22T12:00:00Z"}, "message": "Registration successful"}, "error": null}
		Auth.POST("/register", UserController.RegisterUserHandler)

		// detail: "Logs in a user with email and password, optionally with 2FA code"
		// type: POST
		// url: BaseURL/api/v1/auth/login
		// requesttype: JSON
		// request structure: {"email": "john@example.com", "password": "password123", "code": "optional_2fa_code"}
		// response structure: {"success": true, "status": 200, "payload": {"access_token": "jwt_token", "refresh_token": "jwt_token", "expires_in": 3600, "user_id": "uuid", "user_profile": {"user_id": "uuid", "username": "johndoe", "first_name": "John", "last_name": "Doe", "email": "john@example.com", "country": "US", "bio": "", "primary_language_id": "en", "mute_notifications": false, "socials": {}, "created_at": "2025-04-22T12:00:00Z", "updated_at": "2025-04-22T12:00:00Z"}, "message": "Login successful"}, "error": null}
		Auth.POST("/login", UserController.LoginUserHandler)

		// detail: "Initiates Google OAuth login by providing a redirect URL"
		// type: GET
		// url: BaseURL/api/v1/auth/google/login
		// requesttype: None
		// request structure: {}
		// response structure: {"success": true, "status": 200, "payload": {"url": "https://accounts.google.com/o/oauth2/v2/auth?..."}, "error": null}
		Auth.GET("/google/login", UserController.GoogleLoginInitiate)

		// detail: "Handles Google OAuth callback and redirects to frontend with tokens"
		// type: GET
		// url: BaseURL/api/v1/auth/google/callback
		// requesttype: QueryParams
		// request structure: {"code": "google_auth_code"}
		// response structure: Redirects to frontend URL with query params like ?success=true&accessToken=jwt_token&refreshToken=jwt_token&expiresIn=3600&userID=uuid
		Auth.GET("/google/callback", UserController.GoogleLoginCallback)

		// detail: "Refreshes an access token using a refresh token"
		// type: POST
		// url: BaseURL/api/v1/auth/token/refresh
		// requesttype: JSON
		// request structure: {"refresh_token": "jwt_token"}
		// response structure: {"success": true, "status": 200, "payload": {"access_token": "new_jwt_token", "expires_in": 3600, "user_id": "uuid", "message": "Token refreshed"}, "error": null}
		Auth.POST("/token/refresh", UserController.TokenRefreshHandler)

		// detail: "Verifies a user's email with a token sent via email"
		// type: GET
		// url: BaseURL/api/v1/auth/verify
		// requesttype: QueryParams
		// request structure: {"email": "user@example.com", "token": "verification_token"}
		// response structure: {"success": true, "status": 200, "payload": {"message": "User verified", "user_id": "uuid"}, "error": null}
		Auth.GET("/verify", UserController.VerifyUserHandler)

		// detail: "Resends a verification email to the user"
		// type: GET
		// url: BaseURL/api/v1/auth/verify/resend
		// requesttype: QueryParams
		// request structure: {"email": "user@example.com"}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Verification email resent", "expiry_at": "2025-04-22T12:30:00Z"}, "error": null}
		Auth.GET("/verify/resend", UserController.ResendEmailVerificationHandler)

		// detail: "Initiates a password reset by sending a reset email"
		// type: POST
		// url: BaseURL/api/v1/auth/password/forgot
		// requesttype: JSON
		// request structure: {"email": "user@example.com"}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Password reset email sent", "token": "reset_token"}, "error": null}
		Auth.POST("/password/forgot", UserController.ForgotPasswordHandler)

		// detail: "Completes the password reset process with a token"
		// type: POST
		// url: BaseURL/api/v1/auth/password/reset
		// requesttype: JSON
		// request structure: {"email": "user@example.com", "token": "reset_token", "new_password": "new_password", "confirm_password": "new_password"}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Password reset successful", "user_id": "uuid"}, "error": null}
		Auth.POST("/password/reset", UserController.FinishForgotPasswordHandler)

		// detail: "Checks the 2FA status for a user's email"
		// type: GET
		// url: BaseURL/api/v1/auth/2fa/status
		// requesttype: QueryParams
		// request structure: {"email": "user@example.com"}
		// response structure: {"success": true, "status": 200, "payload": {"is_enabled": true, "message": "2FA status retrieved"}, "error": null}
		Auth.GET("/2fa/status", UserController.GetTwoFactorAuthStatusHandler)
	}
}

// SetUpProtectedUserRoutes defines endpoints for authenticated users (USER role) with public and private subgroups
func SetUpProtectedUserRoutes(ApiV1 *gin.RouterGroup, UserController *controller.UserController, JWTSecret string) {
	Users := ApiV1.Group("/users")

	// Public subgroup (no authentication required)
	UsersPublic := Users.Group("")
	{
		// detail: "Retrieves a user's public profile by username or user_id"
		// type: GET
		// url: BaseURL/api/v1/users/public/profile
		// requesttype: QueryParams
		// request structure: {"username": "johndoe"} or {"user_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"user_profile": {"user_id": "uuid", "username": "johndoe", "first_name": "John", "last_name": "Doe", "country": "US", "bio": "Software engineer", "socials": {"github": "https://github.com/johndoe", "twitter": "https://twitter.com/johndoe"}, "created_at": "2025-04-22T12:00:00Z"}, "message": "Profile retrieved"}, "error": null}
		UsersPublic.GET("/public/profile", UserController.GetUserProfilePublicHandler)

		// detail: "Checks if a username is available for registration"
		// type: GET
		// url: BaseURL/api/v1/users/username/available
		// requesttype: QueryParams
		// request structure: {"username": "johndoe"}
		// response structure: {"success": true, "status": 200, "payload": {"available": true, "message": "Username is available"}, "error": null}
		UsersPublic.GET("/username/available", UserController.UserAvailable)
	}

	// Private subgroup (requires JWT, USER role, and ban check)
	UsersPrivate := Users.Group("")
	UsersPrivate.Use(
		middleware.JWTAuthMiddleware(JWTSecret),
		middleware.RoleAuthMiddleware(middleware.RoleUser, middleware.RoleAdmin),
		middleware.UserBanCheckMiddleware(UserController.GetUserClient()),
	)
	{
		// Profile management subgroup
		Profile := UsersPrivate.Group("/profile")
		{
			// detail: "Gets the authenticated user's profile"
			// type: GET
			// url: BaseURL/api/v1/users/profile
			// requesttype: None
			// request structure: {}
			// response structure: {"success": true, "status": 200, "payload": {"user_profile": {"user_id": "uuid", "username": "johndoe", "first_name": "John", "last_name": "Doe", "email": "john@example.com", "country": "US", "bio": "Software engineer", "primary_language_id": "en", "mute_notifications": false, "socials": {"github": "https://github.com/johndoe"}, "avatar_url": "https://cdn.example.com/avatars/johndoe.jpg", "created_at": "2025-04-22T12:00:00Z", "updated_at": "2025-04-22T12:00:00Z"}, "message": "Profile retrieved"}, "error": null}
			Profile.GET("", UserController.GetUserProfileHandler)

			// detail: "Updates the authenticated user's profile details"
			// type: PUT
			// url: BaseURL/api/v1/users/profile/update
			// requesttype: JSON
			// request structure: {"user_name": "new_johndoe", "first_name": "John", "last_name": "Doe", "country": "US", "bio": "Updated bio", "primary_language_id": "en", "mute_notifications": false, "socials": {"github": "https://github.com/johndoe", "twitter": "https://twitter.com/johndoe"}}
			// response structure: {"success": true, "status": 200, "payload": {"message": "Profile updated", "user_profile": {"user_id": "uuid", "username": "new_johndoe", "first_name": "John", "last_name": "Doe", "email": "john@example.com", "country": "US", "bio": "Updated bio", "primary_language_id": "en", "mute_notifications": false, "socials": {"github": "https://github.com/johndoe", "twitter": "https://twitter.com/johndoe"}, "avatar_url": "https://cdn.example.com/avatars/johndoe.jpg", "created_at": "2025-04-22T12:00:00Z", "updated_at": "2025-04-22T12:30:00Z"}}, "error": null}
			Profile.PUT("/update", UserController.UpdateProfileHandler)

			// detail: "Updates the authenticated user's profile image"
			// type: PATCH
			// url: BaseURL/api/v1/users/profile/image
			// requesttype: FormData
			// request structure: {"avatar": "file_data"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "Image updated", "avatar_url": "https://cdn.example.com/avatars/johndoe_new.jpg"}, "error": null}
			Profile.PATCH("/image", UserController.UpdateProfileImageHandler)

			// detail: "Retrieves the authenticated user's ban history"
			// type: GET
			// url: BaseURL/api/v1/users/profile/ban-history
			// requesttype: None
			// request structure: {}
			// response structure: {"success": true, "status": 200, "payload": {"bans": [{"ban_id": "uuid", "ban_type": "TEMPORARY", "ban_reason": "Violation of terms", "ban_expiry": "2025-05-22T12:00:00Z", "created_at": "2025-04-22T12:00:00Z"}], "message": "Ban history retrieved"}, "error": null}
			Profile.GET("/ban-history", UserController.BanHistoryHandler)
		}

		// Social follow system subgroup
		Follow := UsersPrivate.Group("/follow")
		{
			// detail: "Follows another user"
			// type: POST
			// url: BaseURL/api/v1/users/follow
			// requesttype: QueryParams
			// request structure: {"followee_id": "uuid"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "Followed successfully", "followee_id": "uuid"}, "error": null}
			Follow.POST("", UserController.FollowUserHandler)

			// detail: "Unfollows another user"
			// type: DELETE
			// url: BaseURL/api/v1/users/follow
			// requesttype: QueryParams
			// request structure: {"followee_id": "uuid"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "Unfollowed successfully", "followee_id": "uuid"}, "error": null}
			Follow.DELETE("", UserController.UnfollowUserHandler)

			// detail: "Lists users the specified or authenticated user is following"
			// type: GET
			// url: BaseURL/api/v1/users/follow/following
			// requesttype: QueryParams
			// request structure: {"user_id": "uuid (optional)", "page_token": "abc", "limit": 10}
			// response structure: {"success": true, "status": 200, "payload": {"users": [{"user_id": "uuid", "username": "janedoe", "first_name": "Jane", "last_name": "Doe", "country": "US", "bio": "Developer", "avatar_url": "https://cdn.example.com/avatars/janedoe.jpg"}], "total_count": 10, "next_page_token": "xyz", "message": "Following list retrieved"}, "error": null}
			Follow.GET("/following", UserController.GetFollowingHandler)

			// detail: "Lists users following the specified or authenticated user"
			// type: GET
			// url: BaseURL/api/v1/users/follow/followers
			// requesttype: QueryParams
			// request structure: {"user_id": "uuid (optional)", "page_token": "abc", "limit": 10}
			// response structure: {"success": true, "status": 200, "payload": {"users": [{"user_id": "uuid", "username": "janedoe", "first_name": "Jane", "last_name": "Doe", "country": "US", "bio": "Developer", "avatar_url": "https://cdn.example.com/avatars/janedoe.jpg"}], "total_count": 10, "next_page_token": "xyz", "message": "Followers list retrieved"}, "error": null}
			Follow.GET("/followers", UserController.GetFollowersHandler)

			// detail: "Checks if the authenticated user follows or is followed by another user"
			// type: GET
			// url: BaseURL/api/v1/users/follow/check
			// requesttype: QueryParams
			// request structure: {"user_id": "uuid"}
			// response structure: {"success": true, "status": 200, "payload": {"is_following": true, "is_follower": false, "user_id": "uuid"}, "error": null}
			Follow.GET("/check", UserController.GetFollowFollowingCheckHandler)
		}

		// Security settings subgroup
		Security := UsersPrivate.Group("/security")
		{
			// detail: "Changes the authenticated user's password"
			// type: POST
			// url: BaseURL/api/v1/users/security/password/change
			// requesttype: JSON
			// request structure: {"old_password": "old", "new_password": "new", "confirm_password": "new"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "Password changed successfully", "user_id": "uuid"}, "error": null}
			Security.POST("/password/change", UserController.ChangePasswordHandler)

			// detail: "Sets up 2FA for the authenticated user"
			// type: POST
			// url: BaseURL/api/v1/users/security/2fa/setup
			// requesttype: JSON
			// request structure: {"password": "password"}
			// response structure: {"success": true, "status": 200, "payload": {"image": "qr_code_base64", "secret": "2fa_secret", "message": "2FA setup initiated"}, "error": null}
			Security.POST("/2fa/setup", UserController.SetUpTwoFactorAuthHandler)

			// detail: "Verifies 2FA setup with an OTP"
			// type: POST
			// url: BaseURL/api/v1/users/security/2fa/verify
			// requesttype: JSON
			// request structure: {"otp": "123456"}
			// response structure: {"success": true, "status": 200, "payload": {"verified": true, "message": "2FA verified", "user_id": "uuid"}, "error": null}
			Security.POST("/2fa/verify", UserController.VerifyTwoFactorAuth)

			// detail: "Disables 2FA for the authenticated user"
			// type: DELETE
			// url: BaseURL/api/v1/users/security/2fa/setup
			// requesttype: JSON
			// request structure: {"password": "password", "otp": "123456"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "2FA disabled", "user_id": "uuid"}, "error": null}
			Security.DELETE("/2fa/setup", UserController.DisableTwoFactorAuthHandler)
		}

		// detail: "Searches for users based on a query"
		// type: GET
		// url: BaseURL/api/v1/users/search
		// requesttype: QueryParams
		// request structure: {"query": "john", "page_token": "abc", "limit": 10}
		// response structure: {"success": true, "status": 200, "payload": {"users": [{"user_id": "uuid", "username": "johndoe", "first_name": "John", "last_name": "Doe", "country": "US", "bio": "Software engineer", "avatar_url": "https://cdn.example.com/avatars/johndoe.jpg"}], "total_count": 10, "next_page_token": "xyz", "message": "Search results retrieved"}, "error": null}
		UsersPrivate.GET("/search", UserController.SearchUsersHandler)

		// detail: "Logs out the authenticated user"
		// type: POST
		// url: BaseURL/api/v1/users/logout
		// requesttype: None
		// request structure: {}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Logged out successfully", "user_id": "uuid"}, "error": null}
		UsersPrivate.POST("/logout", UserController.LogoutUserHandler)
	}
}

// SetUpAdminRoutes defines endpoints for admin operations (ADMIN role)
func SetUpAdminRoutes(ApiV1 *gin.RouterGroup, UserController *controller.UserController, JWTSecret string) {
	AdminRoot := ApiV1.Group("/admin")
	{
		// Public admin route (no JWT required)
		AdminPublic := AdminRoot.Group("")
		{
			// detail: "Logs in an admin user"
			// type: POST
			// url: BaseURL/api/v1/admin/login
			// requesttype: JSON
			// request structure: {"email": "admin@example.com", "password": "password"}
			// response structure: {"success": true, "status": 200, "payload": {"access_token": "jwt_token", "refresh_token": "jwt_token", "expires_in": 3600, "admin_id": "uuid", "message": "Login successful"}, "error": null}
			AdminPublic.POST("/login", UserController.LoginAdminHandler)
		}

		// Private admin route (requires JWT and ADMIN role)
		AdminUsers := AdminRoot.Group("/users")
		AdminUsers.Use(
			middleware.JWTAuthMiddleware(JWTSecret),
			middleware.RoleAuthMiddleware(middleware.RoleAdmin),
		)
		{
			// detail: "Lists all users with optional filters"
			// type: GET
			// url: BaseURL/api/v1/admin/users
			// requesttype: QueryParams
			// request structure: {"page_token": "abc", "limit": 10, "role_filter": "USER", "status_filter": "active"}
			// response structure: {"success": true, "status": 200, "payload": {"users": [{"user_id": "uuid", "username": "johndoe", "first_name": "John", "last_name": "Doe", "email": "john@example.com", "role": "USER", "status": "active", "created_at": "2025-04-22T12:00:00Z", "updated_at": "2025-04-22T12:00:00Z"}], "total_count": 10, "next_page_token": "xyz", "message": "Users retrieved"}, "error": null}
			AdminUsers.GET("", UserController.GetAllUsersHandler)

			// detail: "Creates a new user by an admin"
			// type: POST
			// url: BaseURL/api/v1/admin/users
			// requesttype: JSON
			// request structure: {"first_name": "Admin", "last_name": "User", "role": "ADMIN", "email": "admin@example.com", "auth_type": "EMAIL", "password": "password", "confirm_password": "password"}
			// response structure: {"success": true, "status": 200, "payload": {"user_id": "uuid", "message": "User created"}, "error": null}
			AdminUsers.POST("", UserController.CreateUserAdminHandler)

			// detail: "Updates a user's details by an admin"
			// type: PUT
			// url: BaseURL/api/v1/admin/users/update
			// requesttype: JSON
			// request structure: {"user_id": "uuid", "first_name": "Updated", "last_name": "User", "country": "US", "role": "USER", "email": "updated@example.com", "password": "new_password", "primary_language_id": "en", "mute_notifications": false, "socials": {"github": "https://github.com/user", "twitter": "https://twitter.com/user"}}
			// response structure: {"success": true, "status": 200, "payload": {"message": "User updated", "user_id": "uuid"}, "error": null}
			AdminUsers.PUT("/update", UserController.UpdateUserAdminHandler)

			// detail: "Soft deletes a user by an admin"
			// type: DELETE
			// url: BaseURL/api/v1/admin/users/soft-delete
			// requesttype: QueryParams
			// request structure: {"user_id": "uuid"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "User soft deleted", "user_id": "uuid"}, "error": null}
			AdminUsers.DELETE("/soft-delete", UserController.SoftDeleteUserAdminHandler)

			// detail: "Verifies a user by an admin"
			// type: POST
			// url: BaseURL/api/v1/admin/users/verify
			// requesttype: QueryParams
			// request structure: {"user_id": "uuid"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "User verified", "user_id": "uuid"}, "error": null}
			AdminUsers.POST("/verify", UserController.VerifyAdminUserHandler)

			// detail: "Unverifies a user by an admin"
			// type: POST
			// url: BaseURL/api/v1/admin/users/unverify
			// requesttype: QueryParams
			// request structure: {"user_id": "uuid"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "User unverified", "user_id": "uuid"}, "error": null}
			AdminUsers.POST("/unverify", UserController.UnverifyUserHandler)

			// detail: "Bans a user by an admin"
			// type: POST
			// url: BaseURL/api/v1/admin/users/ban
			// requesttype: JSON
			// request structure: {"user_id": "uuid", "ban_type": "TEMPORARY", "ban_reason": "Violation of terms", "ban_expiry": "2025-05-22T12:00:00Z"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "User banned", "user_id": "uuid", "ban_id": "uuid"}, "error": null}
			AdminUsers.POST("/ban", UserController.BanUserHandler)

			// detail: "Unbans a user by an admin"
			// type: POST
			// url: BaseURL/api/v1/admin/users/unban
			// requesttype: QueryParams
			// request structure: {"user_id": "uuid"}
			// response structure: {"success": true, "status": 200, "payload": {"message": "User unbanned", "user_id": "uuid"}, "error": null}
			AdminUsers.POST("/unban", UserController.UnbanUserHandler)

			// detail: "Retrieves a user's ban history by an admin"
			// type: GET
			// url: BaseURL/api/v1/admin/users/ban-history
			// requesttype: QueryParams
			// request structure: {"user_id": "uuid"}
			// response structure: {"success": true, "status": 200, "payload": {"bans": [{"ban_id": "uuid", "ban_type": "TEMPORARY", "ban_reason": "Violation of terms", "ban_expiry": "2025-05-22T12:00:00Z", "created_at": "2025-04-22T12:00:00Z"}], "message": "Ban history retrieved"}, "error": null}
			AdminUsers.GET("/ban-history", UserController.BanHistoryHandler)
		}
	}
}

// SetUpCompilerRoutes defines compiler-related endpoints
func SetUpCompilerRoutes(ApiV1 *gin.RouterGroup, CompilerController *controller.CompilerController) {
	Compiler := ApiV1.Group("")
	{
		// detail: "Compiles and runs user-submitted code"
		// type: POST
		// url: BaseURL/api/v1/compile
		// requesttype: JSON
		// request structure: {"code": "package main\nfunc main() { fmt.Println(\"Hello\") }", "language": "go", "input": "input data"}
		// response structure: {"success": true, "status": 200, "payload": {"output": "Hello\n", "error": "", "execution_time_ms": 120, "memory_used_kb": 2048}, "error": null}
		Compiler.POST("/compile", CompilerController.CompileCodeHandler)
	}
}

// SetUpProblemRoutes defines problem-related endpoints with public and private subgroups
func SetUpProblemRoutes(ApiV1 *gin.RouterGroup, ProblemController *controller.ProblemController, JWTSecret string, UserController *controller.UserController) {
	Problems := ApiV1.Group("/problems")

	// Public subgroup (no authentication required)
	ProblemsPublic := Problems.Group("")
	{
		// detail: "Lists all problems with pagination and filters"
		// type: GET
		// url: BaseURL/api/v1/problems/list
		// requesttype: QueryParams
		// request structure: {"page": 1, "page_size": 10, "tags": "array,math", "difficulty": "easy", "search_query": "two sum"}
		// response structure: {"success": true, "status": 200, "payload": {"problems": [{"problem_id": "uuid", "title": "Two Sum", "slug": "two-sum", "difficulty": "easy", "tags": ["array", "math"], "acceptance_rate": 0.75, "total_submissions": 1000, "created_at": "2025-04-22T12:00:00Z"}], "total_count": 50, "page": 1, "page_size": 10, "message": "Problems retrieved"}, "error": null}
		ProblemsPublic.GET("/list", ProblemController.ListProblemsHandler)

		// detail: "Gets problem metadata by ID or slug"
		// type: GET
		// url: BaseURL/api/v1/problems/metadata
		// requesttype: QueryParams
		// request structure: {"problem_id": "uuid"} or {"slug": "two-sum"}
		// response structure: {"success": true, "status": 200, "payload": {"problem_metadata": {"problem_id": "uuid", "title": "Two Sum", "slug": "two-sum", "difficulty": "easy", "description": "Given an array...", "tags": ["array", "math"], "acceptance_rate": 0.75, "total_submissions": 1000, "supported_languages": ["go", "python"], "created_at": "2025-04-22T12:00:00Z"}, "message": "Problem metadata retrieved"}, "error": null}
		ProblemsPublic.GET("/metadata", ProblemController.GetProblemByIDSlugHandler)

		// detail: "Lists problem metadata with pagination and filters"
		// type: GET
		// url: BaseURL/api/v1/problems/metadata/list
		// requesttype: QueryParams
		// request structure: {"page": 1, "page_size": 10, "tags": "array,math", "difficulty": "easy", "search_query": "two sum"}
		// response structure: {"success": true, "status": 200, "payload": {"problems": [{"problem_id": "uuid", "title": "Two Sum", "slug": "two-sum", "difficulty": "easy", "tags": ["array", "math"], "acceptance_rate": 0.75, "total_submissions": 1000, "created_at": "2025-04-22T12:00:00Z"}], "total_count": 50, "page": 1, "page_size": 10, "message": "Problem metadata retrieved"}, "error": null}
		ProblemsPublic.GET("/metadata/list", ProblemController.GetProblemMetadataListHandler)

		// detail: "Gets the top 10 global leaderboard"
		// type: GET
		// url: BaseURL/api/v1/problems/leaderboard/top10
		// requesttype: QueryParams
		// request structure: {"k": 10}
		// response structure: {"success": true, "status": 200, "payload": {"users": [{"user_id": "uuid", "username": "johndoe", "score": 1500, "problems_solved": 50, "rank": 1}], "message": "Top 10 leaderboard retrieved"}, "error": null}
		ProblemsPublic.GET("/leaderboard/top10", ProblemController.GetTopKGlobalController)

		// detail: "Gets the top 10 leaderboard for a specific entity"
		// type: GET
		// url: BaseURL/api/v1/problems/leaderboard/top10/entity
		// requesttype: QueryParams
		// request structure: {"entity": "company_x", "k": 10}
		// response structure: {"success": true, "status": 200, "payload": {"users": [{"user_id": "uuid", "username": "johndoe", "score": 1500, "problems_solved": 50, "rank": 1}], "message": "Top 10 entity leaderboard retrieved"}, "error": null}
		ProblemsPublic.GET("/leaderboard/top10/entity", ProblemController.GetTopKEntityController)
	}

	// Private subgroup (requires JWT, USER role, and ban check)
	ProblemsPrivate := Problems.Group("")
	ProblemsPrivate.Use(
		middleware.JWTAuthMiddleware(JWTSecret),
		middleware.RoleAuthMiddleware(middleware.RoleUser, middleware.RoleAdmin),
		middleware.UserBanCheckMiddleware(UserController.GetUserClient()),
	)
	{
		// detail: "Creates a new problem"
		// type: POST
		// url: BaseURL/api/v1/problems/
		// requesttype: JSON
		// request structure: {"title": "New Problem", "description": "Solve this...", "tags": ["array", "math"], "difficulty": "easy"}
		// response structure: {"success": true, "status": 200, "payload": {"problem_id": "uuid", "slug": "new-problem", "message": "Problem created"}, "error": null}
		ProblemsPublic.POST("/", ProblemController.CreateProblemHandler)

		// detail: "Updates an existing problem"
		// type: PUT
		// url: BaseURL/api/v1/problems/
		// requesttype: JSON
		// request structure: {"problem_id": "uuid", "title": "Updated Problem", "description": "Updated description...", "tags": ["array"], "difficulty": "medium"}
		// response structure: {"success": true, "status": 200, "payload": {"problem_id": "uuid", "message": "Problem updated"}, "error": null}
		ProblemsPublic.PUT("/", ProblemController.UpdateProblemHandler)

		// detail: "Deletes a problem"
		// type: DELETE
		// url: BaseURL/api/v1/problems/
		// requesttype: QueryParams
		// request structure: {"problem_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"problem_id": "uuid", "message": "Problem deleted"}, "error": null}
		ProblemsPublic.DELETE("/", ProblemController.DeleteProblemHandler)

		// detail: "Gets a problem by ID"
		// type: GET
		// url: BaseURL/api/v1/problems/
		// requesttype: QueryParams
		// request structure: {"problem_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"problem": {"problem_id": "uuid", "title": "Two Sum", "slug": "two-sum", "difficulty": "easy", "description": "Given an array...", "tags": ["array", "math"], "supported_languages": ["go", "python"], "test_cases": {"run": [{"input": "1 2", "expected": "3"}], "submit": [{"input": "1 2", "expected": "3"}]}, "created_at": "2025-04-22T12:00:00Z"}, "message": "Problem retrieved"}, "error": null}
		ProblemsPublic.GET("/", ProblemController.GetProblemHandler)

		// detail: "Adds test cases to a problem"
		// type: POST
		// url: BaseURL/api/v1/problems/testcases
		// requesttype: JSON
		// request structure: {"problem_id": "uuid", "testcases": {"run": [{"input": "1 2", "expected": "3"}], "submit": [{"input": "4 5", "expected": "9"}]}}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Test cases added", "added_count": 2, "problem_id": "uuid"}, "error": null}
		ProblemsPublic.POST("/testcases", ProblemController.AddTestCasesHandler)

		// detail: "Deletes a single test case from a problem"
		// type: DELETE
		// url: BaseURL/api/v1/problems/testcases/single
		// requesttype: JSON
		// request structure: {"problem_id": "uuid", "testcase_id": "testcase_uuid", "is_run_testcase": true}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Test case deleted", "problem_id": "uuid", "testcase_id": "testcase_uuid"}, "error": null}
		ProblemsPublic.DELETE("/testcases/single", ProblemController.DeleteTestCaseHandler)

		// detail: "Adds language support to a problem"
		// type: POST
		// url: BaseURL/api/v1/problems/language
		// requesttype: JSON
		// request structure: {"problem_id": "uuid", "language": "go", "validation_code": {"placeholder": "func main() {}", "code": "func validate(input string) string {}", "template": "package main\nimport \"fmt\"\nfunc main() {}"}}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Language support added", "problem_id": "uuid", "language": "go"}, "error": null}
		ProblemsPublic.POST("/language", ProblemController.AddLanguageSupportHandler)

		// detail: "Updates language support for a problem"
		// type: PUT
		// url: BaseURL/api/v1/problems/language
		// requesttype: JSON
		// request structure: {"problem_id": "uuid", "language": "go", "validation_code": {"placeholder": "func main() {}", "code": "func validate(input string) string {}", "template": "package main\nimport \"fmt\"\nfunc main() {}"}}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Language support updated", "problem_id": "uuid", "language": "go"}, "error": null}
		ProblemsPublic.PUT("/language", ProblemController.UpdateLanguageSupportHandler)

		// detail: "Removes language support from a problem"
		// type: DELETE
		// url: BaseURL/api/v1/problems/language
		// requesttype: JSON
		// request structure: {"problem_id": "uuid", "language": "go"}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Language support removed", "problem_id": "uuid", "language": "go"}, "error": null}
		ProblemsPublic.DELETE("/language", ProblemController.RemoveLanguageSupportHandler)

		// detail: "Validates a problem by ID"
		// type: GET
		// url: BaseURL/api/v1/problems/validate
		// requesttype: QueryParams
		// request structure: {"problem_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"message": "Validation successful", "problem_id": "uuid", "validation_status": "valid"}, "error": null}
		ProblemsPublic.GET("/validate", ProblemController.FullValidationByProblemIDHandler)

		// detail: "Gets supported languages for a problem"
		// type: GET
		// url: BaseURL/api/v1/problems/languages
		// requesttype: QueryParams
		// request structure: {"problem_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"supported_languages": ["go", "python"], "validate_code": {"go": {"placeholder": "func main() {}", "code": "func validate(input string) string {}", "template": "package main\nimport \"fmt\"\nfunc main() {}"}}, "message": "Languages retrieved", "problem_id": "uuid"}, "error": null}
		ProblemsPublic.GET("/languages", ProblemController.GetLanguageSupportsHandler)

		// detail: "Executes user code against a problem's test cases"
		// type: POST
		// url: BaseURL/api/v1/problems/execute
		// requesttype: JSON
		// request structure: {"problem_id": "uuid", "user_code": "func add(a, b int) int { return a + b }", "language": "go", "is_run_testcase": true}
		// response structure: {"success": true, "status": 200, "payload": {"problem_id": "uuid", "language": "go", "is_run_testcase": true, "rawoutput": {"passed": true, "results": [{"testcase_id": "uuid", "input": "1 2", "expected": "3", "actual": "3", "passed": true}], "execution_time_ms": 120, "memory_used_kb": 2048}, "message": "Code executed"}, "error": null}
		ProblemsPrivate.POST("/execute", ProblemController.RunUserCodeProblemHandler)

		// detail: "Gets submission history for a user, optionally filtered by problem"
		// type: GET
		// url: BaseURL/api/v1/problems/submission/history
		// requesttype: QueryParams
		// request structure: {"user_id": "uuid", "problem_id": "uuid (optional)", "page": 1, "limit": 10}
		// response structure: {"success": true, "status": 200, "payload": {"submissions": [{"submission_id": "uuid", "problem_id": "uuid", "user_id": "uuid", "language": "go", "code": "func add(a, b int) int { return a + b }", "status": "ACCEPTED", "execution_time_ms": 120, "memory_used_kb": 2048, "submitted_at": "2025-04-22T12:00:00Z"}], "total_count": 10, "page": 1, "limit": 10, "message": "Submission history retrieved"}, "error": null}
		ProblemsPublic.GET("/submission/history", ProblemController.GetSubmissionHistoryOptionalProblemId)

		// detail: "Gets problem statistics for a user"
		// type: GET
		// url: BaseURL/api/v1/problems/stats
		// requesttype: QueryParams
		// request structure: {"user_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"data": {"user_id": "uuid", "total_problems_solved": 50, "easy_solved": 20, "medium_solved": 20, "hard_solved": 10, "total_submissions": 100, "acceptance_rate": 0.75}, "message": "Problem statistics retrieved"}, "error": null}
		ProblemsPublic.GET("/stats", ProblemController.GetProblemStatistics)

		// detail: "Gets monthly activity heatmap for a user"
		// type: GET
		// url: BaseURL/api/v1/problems/activity
		// requesttype: QueryParams
		// request structure: {"user_id": "uuid", "year": 2025, "month": 4}
		// response structure: {"success": true, "status": 200, "payload": {"data": [{"date": "2025-04-01", "submission_count": 5}, {"date": "2025-04-02", "submission_count": 3}], "message": "Activity heatmap retrieved"}, "error": null}
		ProblemsPublic.GET("/activity", ProblemController.GetMonthlyActivityHeatmapController)

		// detail: "Gets a user's rank globally and within their entity"
		// type: GET
		// url: BaseURL/api/v1/problems/leaderboard/rank
		// requesttype: QueryParams
		// request structure: {"user_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"global_rank": 100, "entity_rank": 10, "user_id": "uuid", "message": "Rank retrieved"}, "error": null}
		ProblemsPrivate.GET("/leaderboard/rank", ProblemController.GetUserRankController)

		// detail: "Gets comprehensive leaderboard data for a user"
		// type: GET
		// url: BaseURL/api/v1/problems/leaderboard/data
		// requesttype: QueryParams
		// request structure: {"user_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"user_id": "uuid", "score": 1500.0, "entity": "company_x", "global_rank": 100, "entity_rank": 10, "top_k_global": [{"user_id": "uuid", "username": "johndoe", "score": 1500, "rank": 1}], "top_k_entity": [{"user_id": "uuid", "username": "johndoe", "score": 1500, "rank": 1}], "message": "Leaderboard data retrieved"}, "error": null}
		ProblemsPublic.GET("/leaderboard/data", ProblemController.GetLeaderboardDataController)
	}

	// Challenge routes (requires JWT, USER role, and ban check)
	Challenges := ApiV1.Group("")
	Challenges.Use(
		middleware.JWTAuthMiddleware(JWTSecret),
		middleware.RoleAuthMiddleware(middleware.RoleUser, middleware.RoleAdmin),
		middleware.UserBanCheckMiddleware(UserController.GetUserClient()),
	)
	{
		// detail: "Creates a new challenge"
		// type: POST
		// url: BaseURL/api/v1/challenges
		// requesttype: JSON
		// request structure: {"title": "Test Challenge", "creator_id": "uuid", "difficulty": "medium", "is_private": false, "problem_ids": ["uuid1", "uuid2"], "time_limit": 3600, "expected_start": "2025-04-22T12:00:00Z"}
		// response structure: {"success": true, "status": 200, "payload": {"id": "uuid", "password": "pass123", "join_url": "https://platform.example.com/challenges/join/uuid", "message": "Challenge created"}, "error": null}
		Challenges.POST("/challenges", ProblemController.CreateChallenge)

		// detail: "Gets details of a challenge"
		// type: GET
		// url: BaseURL/api/v1/challenges/details
		// requesttype: QueryParams
		// request structure: {"challenge_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"challenge": {"id": "uuid", "title": "Test Challenge", "creator_id": "uuid", "difficulty": "medium", "is_private": false, "problem_ids": ["uuid1", "uuid2"], "time_limit": 3600, "start_time": "2025-04-22T12:00:00Z", "end_time": "2025-04-22T13:00:00Z", "status": "active"}, "leaderboard": [{"user_id": "uuid", "username": "johndoe", "score": 100, "rank": 1}], "message": "Challenge details retrieved"}, "error": null}
		Challenges.GET("/challenges/details", ProblemController.GetChallengeDetails)

		// detail: "Lists public challenges with filters"
		// type: GET
		// url: BaseURL/api/v1/challenges/public
		// requesttype: QueryParams
		// request structure: {"difficulty": "medium", "is_active": true, "page": 1, "page_size": 10, "user_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"challenges": [{"id": "uuid", "title": "Test Challenge", "creator_id": "uuid", "difficulty": "medium", "is_private": false, "time_limit": 3600, "start_time": "2025-04-22T12:00:00Z", "status": "active"}], "total_count": 10, "page": 1, "page_size": 10, "message": "Public challenges retrieved"}, "error": null}
		Challenges.GET("/challenges/public", ProblemController.GetPublicChallenge)

		// detail: "Joins a challenge (public or private with password)"
		// type: POST
		// url: BaseURL/api/v1/challenges/join
		// requesttype: JSON
		// request structure: {"challenge_id": "uuid", "user_id": "uuid"} or {"challenge_id": "uuid", "user_id": "uuid", "password": "pass123"}
		// response structure: {"success": true, "status": 200, "payload": {"challenge_id": "uuid", "user_id": "uuid", "message": "Joined successfully"}, "error": null}
		Challenges.POST("/challenges/join", ProblemController.JoinChallenge)

		// detail: "Starts a challenge for a user"
		// type: POST
		// url: BaseURL/api/v1/challenges/start
		// requesttype: JSON
		// request structure: {"challenge_id": "uuid", "user_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"challenge_id": "uuid", "user_id": "uuid", "start_time": "2025-04-22T12:00:00Z", "message": "Challenge started"}, "error": null}
		Challenges.POST("/challenges/start", ProblemController.StartChallenge)

		// detail: "Ends a challenge for a user"
		// type: POST
		// url: BaseURL/api/v1/challenges/end
		// requesttype: JSON
		// request structure: {"challenge_id": "uuid", "user_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"challenge_id": "uuid", "user_id": "uuid", "leaderboard": [{"user_id": "uuid", "username": "johndoe", "score": 100, "rank": 1}], "message": "Challenge ended"}, "error": null}
		Challenges.POST("/challenges/end", ProblemController.EndChallenge)

		// detail: "Gets the status of a submission"
		// type: GET
		// url: BaseURL/api/v1/challenges/submissions/status
		// requesttype: QueryParams
		// request structure: {"submission_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"submission": {"submission_id": "uuid", "challenge_id": "uuid", "user_id": "uuid", "problem_id": "uuid", "language": "go", "code": "func add(a, b int) int { return a + b }", "status": "ACCEPTED", "execution_time_ms": 120, "memory_used_kb": 2048, "submitted_at": "2025-04-22T12:00:00Z"}, "message": "Submission status retrieved"}, "error": null}
		Challenges.GET("/challenges/submissions/status", ProblemController.GetSubmissionStatus)

		// detail: "Gets all submissions for a challenge"
		// type: GET
		// url: BaseURL/api/v1/challenges/submissions
		// requesttype: QueryParams
		// request structure: {"challenge_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"submissions": [{"submission_id": "uuid", "challenge_id": "uuid", "user_id": "uuid", "problem_id": "uuid", "language": "go", "code": "func add(a, b int) int { return a + b }", "status": "ACCEPTED", "execution_time_ms": 120, "memory_used_kb": 2048, "submitted_at": "2025-04-22T12:00:00Z"}], "message": "Challenge submissions retrieved"}, "error": null}
		Challenges.GET("/challenges/submissions", ProblemController.GetChallengeSubmissions)

		// detail: "Gets overall stats for a user across challenges"
		// type: GET
		// url: BaseURL/api/v1/challenges/stats/user
		// requesttype: QueryParams
		// request structure: {"user_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"stats": {"user_id": "uuid", "total_challenges": 10, "challenges_won": 3, "total_problems_solved": 50, "average_score": 85.5}, "message": "User challenge stats retrieved"}, "error": null}
		Challenges.GET("/challenges/stats/user", ProblemController.GetUserStats)

		// detail: "Gets stats for a user in a specific challenge"
		// type: GET
		// url: BaseURL/api/v1/challenges/stats/challenge-user
		// requesttype: QueryParams
		// request structure: {"challenge_id": "uuid", "user_id": "uuid"}
		// response structure: {"success": true, "status": 200, "payload": {"user_id": "uuid", "challenge_id": "uuid", "problems_completed": 5, "total_score": 100, "rank": 1, "challenge_problem_metadata": [{"problem_id": "uuid", "title": "Two Sum", "difficulty": "easy", "solved": true}]}, "message": "Challenge user stats retrieved"}, "error": null}
		Challenges.GET("/challenges/stats/challenge-user", ProblemController.GetChallengeUserStats)

		// detail: "Gets the challenge history for a user"
		// type: GET
		// url: BaseURL/api/v1/challenges/history
		// requesttype: QueryParams
		// request structure: {"user_id": "uuid", "page": 1, "page_size": 10, "is_private": true}
		// response structure: {"success": true, "status": 200, "payload": {"challenges": [{"id": "uuid", "title": "Test Challenge", "creator_id": "uuid", "difficulty": "medium", "is_private": true, "time_limit": 3600, "start_time": "2025-04-22T12:00:00Z", "status": "completed", "user_score": 100, "user_rank": 1}], "total_count": 10, "page": 1, "page_size": 10, "message": "Challenge history retrieved"}, "error": null}
		Challenges.GET("/challenges/history", ProblemController.GetUserChallengeHistory)
	}
}
