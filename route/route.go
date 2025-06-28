package router

import (
	"xcode/clients"
	"xcode/configs"
	"xcode/controller"
	"xcode/middleware"
	"xcode/natsclient"

	"github.com/gin-gonic/gin"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	// ChallengeService "github.com/lijuuu/GlobalProtoXcode/ChallengeService"
	ProblemsService "github.com/lijuuu/GlobalProtoXcode/ProblemsService"
	"go.uber.org/zap"
)

func SetupRoutes(Router *gin.Engine, Clients *clients.ClientConnections, JWTSecret string, log *zap.Logger) {

	//Setup Client Instances
	NatsClient := natsclient.NewNatsClient(configs.LoadConfig().NATSURL, log)
	ProblemClient := ProblemsService.NewProblemsServiceClient(Clients.ConnProblem)
	UserClient := AuthUserAdminService.NewAuthUserAdminServiceClient(Clients.ConnUser)
	// ChallengeClient := ChallengeService.NewChallengeServiceClient(Clients.ConnChallenge)

	//Setup Controller Instances
	UserController := controller.NewUserController(UserClient, ProblemClient)
	CompilerController := controller.NewCompilerController(NatsClient)
	ProblemController := controller.NewProblemController(ProblemClient, UserClient)
	// ChallengeController := controller.NewChallengeController(ChallengeClient, ProblemClient)

	ApiV1 := Router.Group("/api/v1")
	SetUpPublicAuthRoutes(ApiV1, UserController)
	SetUpProtectedUserRoutes(ApiV1, UserController, JWTSecret)
	SetUpAdminRoutes(ApiV1, UserController, JWTSecret)
	SetUpCompilerRoutes(ApiV1, CompilerController)
	SetUpProblemRoutes(ApiV1, ProblemController, JWTSecret, UserController)
	// SetUpChallengeRoutes(ApiV1, ChallengeController, UserController, JWTSecret)
}

func SetUpPublicAuthRoutes(ApiV1 *gin.RouterGroup, UserController *controller.UserController) {
	Auth := ApiV1.Group("/auth")
	{
		Auth.POST("/register", UserController.RegisterUserHandler)
		Auth.POST("/login", UserController.LoginUserHandler)
		Auth.GET("/google/login", UserController.GoogleLoginInitiate)
		Auth.GET("/google/callback", UserController.GoogleLoginCallback)
		Auth.POST("/token/refresh", UserController.TokenRefreshHandler)
		Auth.GET("/verify", UserController.VerifyUserHandler)
		Auth.GET("/verify/resend", UserController.ResendEmailVerificationHandler)
		Auth.POST("/password/forgot", UserController.ForgotPasswordHandler)
		Auth.POST("/password/reset", UserController.FinishForgotPasswordHandler)
		Auth.GET("/2fa/status", UserController.GetTwoFactorAuthStatusHandler)
	}
}

func SetUpProtectedUserRoutes(ApiV1 *gin.RouterGroup, UserController *controller.UserController, JWTSecret string) {
	Users := ApiV1.Group("/users")
	UsersPublic := Users.Group("")
	{
		UsersPublic.GET("/public/profile", UserController.GetUserProfilePublicHandler)
		UsersPublic.GET("/username/available", UserController.UserAvailable)
	}
	UsersPrivate := Users.Group("")
	UsersPrivate.Use(
		middleware.JWTAuthMiddleware(JWTSecret),
		middleware.RoleAuthMiddleware(middleware.RoleUser, middleware.RoleAdmin),
		middleware.UserBanCheckMiddleware(UserController.GetUserClient()),
	)
	{
		Profile := UsersPrivate.Group("/profile")
		{
			Profile.GET("", UserController.GetUserProfileHandler)
			Profile.PUT("/update", UserController.UpdateProfileHandler)
			Profile.PATCH("/image", UserController.UpdateProfileImageHandler)
			Profile.GET("/ban-history", UserController.BanHistoryHandler)
		}
		Follow := UsersPrivate.Group("/follow")
		{
			Follow.POST("", UserController.FollowUserHandler)
			Follow.DELETE("", UserController.UnfollowUserHandler)
			Follow.GET("/following", UserController.GetFollowingHandler)
			Follow.GET("/followers", UserController.GetFollowersHandler)
			Follow.GET("/check", UserController.GetFollowFollowingCheckHandler)
		}
		Security := UsersPrivate.Group("/security")
		{
			Security.POST("/password/change", UserController.ChangePasswordHandler)
			Security.POST("/2fa/setup", UserController.SetUpTwoFactorAuthHandler)
			Security.POST("/2fa/verify", UserController.VerifyTwoFactorAuth)
			Security.DELETE("/2fa/setup", UserController.DisableTwoFactorAuthHandler)
		}
		UsersPrivate.GET("/search", UserController.SearchUsersHandler)
		UsersPrivate.POST("/logout", UserController.LogoutUserHandler)
	}
}

func SetUpAdminRoutes(ApiV1 *gin.RouterGroup, UserController *controller.UserController, JWTSecret string) {
	AdminRoot := ApiV1.Group("/admin")
	{
		AdminPublic := AdminRoot.Group("")
		{
			AdminPublic.POST("/login", UserController.LoginAdminHandler)
		}
		AdminUsers := AdminRoot.Group("/users")
		AdminUsers.Use(
			middleware.JWTAuthMiddleware(JWTSecret),
			middleware.RoleAuthMiddleware(middleware.RoleAdmin),
		)
		{
			AdminUsers.GET("", UserController.GetAllUsersHandler)
			AdminUsers.POST("", UserController.CreateUserAdminHandler)
			AdminUsers.PUT("/update", UserController.UpdateUserAdminHandler)
			AdminUsers.DELETE("/soft-delete", UserController.SoftDeleteUserAdminHandler)
			AdminUsers.POST("/verify", UserController.VerifyAdminUserHandler)
			AdminUsers.POST("/unverify", UserController.UnverifyUserHandler)
			AdminUsers.POST("/ban", UserController.BanUserHandler)
			AdminUsers.POST("/unban", UserController.UnbanUserHandler)
			AdminUsers.GET("/ban-history", UserController.BanHistoryHandler)
		}
	}
}

func SetUpCompilerRoutes(ApiV1 *gin.RouterGroup, CompilerController *controller.CompilerController) {
	Compiler := ApiV1.Group("")
	{
		Compiler.POST("/compile", CompilerController.CompileCodeHandler)
	}
}

func SetUpProblemRoutes(ApiV1 *gin.RouterGroup, ProblemController *controller.ProblemController, JWTSecret string, UserController *controller.UserController) {
	Problems := ApiV1.Group("/problems")
	ProblemsPublic := Problems.Group("")
	{
		ProblemsPublic.GET("/list", ProblemController.ListProblemsHandler)
		ProblemsPublic.GET("/metadata", ProblemController.GetProblemByIDSlugHandler)
		ProblemsPublic.GET("/metadata/list", ProblemController.GetProblemMetadataListHandler)
		ProblemsPublic.GET("/leaderboard/top10", ProblemController.GetTopKGlobalController)
		ProblemsPublic.GET("/leaderboard/top10/entity", ProblemController.GetTopKEntityController)
		ProblemsPublic.GET("/languages", ProblemController.GetLanguageSupportsHandler)
		ProblemsPublic.GET("/bulk/metadata", ProblemController.GetBulkProblemMetadata)
		ProblemsPublic.POST("/execute", ProblemController.RunUserCodeProblemHandler)
		ProblemsPublic.GET("/submission/history", ProblemController.GetSubmissionHistoryOptionalProblemId)
		ProblemsPublic.GET("/stats", ProblemController.GetProblemStatistics)
		ProblemsPublic.GET("/activity", ProblemController.GetMonthlyActivityHeatmapController)
		ProblemsPublic.GET("/leaderboard/data", ProblemController.GetLeaderboardDataController)
	}
	ProblemsPrivate := Problems.Group("")
	ProblemsPrivate.Use(
		middleware.JWTAuthMiddleware(JWTSecret),
		middleware.RoleAuthMiddleware(middleware.RoleAdmin),
	)
	{
		ProblemsPrivate.GET("/list/all", ProblemController.ListProblemsHandler)
		ProblemsPrivate.POST("/", ProblemController.CreateProblemHandler)
		ProblemsPrivate.PUT("/", ProblemController.UpdateProblemHandler)
		ProblemsPrivate.DELETE("/", ProblemController.DeleteProblemHandler)
		ProblemsPrivate.GET("/", ProblemController.GetProblemHandler)
		ProblemsPrivate.POST("/testcases", ProblemController.AddTestCasesHandler)
		ProblemsPrivate.DELETE("/testcases/single", ProblemController.DeleteTestCaseHandler)
		ProblemsPrivate.POST("/language", ProblemController.AddLanguageSupportHandler)
		ProblemsPrivate.PUT("/language", ProblemController.UpdateLanguageSupportHandler)
		ProblemsPrivate.DELETE("/language", ProblemController.RemoveLanguageSupportHandler)
		ProblemsPrivate.GET("/validate", ProblemController.FullValidationByProblemIDHandler)
		ProblemsPrivate.GET("/leaderboard/rank", ProblemController.GetUserRankController)
	}

}

//TODO: migrate to challenge service
// func SetUpChallengeRoutes(ApiV1 *gin.RouterGroup, ChallengeController *controller.ChallengeController, UserController *controller.UserController, JWTSecret string) {
// 	Challenges := ApiV1.Group("")
// 	Challenges.Use(
// 		middleware.JWTAuthMiddleware(JWTSecret),
// 		middleware.RoleAuthMiddleware(middleware.RoleUser, middleware.RoleAdmin),
// 		middleware.UserBanCheckMiddleware(UserController.GetUserClient()),
// 	)
// 	{
// 		Challenges.POST("/challenges", ChallengeController.CreateChallenge)
// 		Challenges.GET("/challenges/details", ChallengeController.GetChallengeDetails)
// 		Challenges.GET("/challenges/public", ChallengeController.GetPublicChallenge)
// 		Challenges.POST("/challenges/join", ChallengeController.JoinChallenge)
// 		Challenges.POST("/challenges/start", ChallengeController.StartChallenge)
// 		Challenges.POST("/challenges/end", ChallengeController.EndChallenge)
// 		Challenges.GET("/challenges/submissions/status", ChallengeController.GetSubmissionStatus)
// 		Challenges.GET("/challenges/submissions", ChallengeController.GetChallengeSubmissions)
// 		Challenges.GET("/challenges/stats/user", ChallengeController.GetUserStats)
// 		Challenges.GET("/challenges/stats/challenge-user", ChallengeController.GetChallengeUserStats)
// 		Challenges.GET("/challenges/history", ChallengeController.GetUserChallengeHistory)
// 	}
// }
