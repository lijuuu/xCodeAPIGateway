package controller

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"xcode/configs"
	"xcode/customerrors"
	"xcode/middleware"
	"xcode/model"
	"xcode/utils"

	cache "xcode/ristretto"

	"github.com/gin-gonic/gin"
	authUserAdminPB "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	problemPB "github.com/lijuuu/GlobalProtoXcode/ProblemsService"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UserController handles user-related API requests
type UserController struct {
	userClient    authUserAdminPB.AuthUserAdminServiceClient
	problemClient problemPB.ProblemsServiceClient
	googleCfg     *oauth2.Config
}

// NewUserController creates a new instance of UserController
func NewUserController(userClient authUserAdminPB.AuthUserAdminServiceClient, problemClient problemPB.ProblemsServiceClient) *UserController {
	config := configs.LoadConfig()
	googleCfg := &oauth2.Config{
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		RedirectURL:  config.GoogleRedirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	return &UserController{
		userClient:    userClient,
		googleCfg:     googleCfg,
		problemClient: problemClient,
	}
}

// GetUserClient returns the user service client for middleware use
func (uc *UserController) GetUserClient() authUserAdminPB.AuthUserAdminServiceClient {
	return uc.userClient
}

// parseGrpcError extracts ErrorType, Code, and Details from the gRPC error message
func parseGrpcError(errorMessage string) (string, codes.Code, string) {
	// Default values
	errorType := customerrors.ERR_GRPC_ERROR
	code := codes.Internal
	details := errorMessage

	// Regular expression to match "ErrorType: <type>, Code: <code>, Details: <details>"
	re := regexp.MustCompile(`ErrorType: ([^,]+), Code: (\d+), Details: (.+)`)
	matches := re.FindStringSubmatch(errorMessage)
	if len(matches) == 4 {
		errorType = matches[1]
		if codeNum, err := strconv.Atoi(matches[2]); err == nil {
			code = codes.Code(codeNum)
		}
		details = matches[3]
	}

	return errorType, code, details
}

// mapGrpcCodeToHttp maps gRPC codes to HTTP status codes
func mapGrpcCodeToHttp(code codes.Code) int {
	switch code {
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.NotFound:
		return http.StatusNotFound
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.Internal:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// Authentication and Security
func (uc *UserController) RegisterUserHandler(c *gin.Context) {
	var req model.RegisterUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	registerUserRequest := &authUserAdminPB.RegisterUserRequest{
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		Email:           req.Email,
		Password:        req.Password,
		ConfirmPassword: req.ConfirmPassword,
		TraceID:         GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.RegisterUser(c.Request.Context(), registerUserRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, _, details := parseGrpcError(grpcStatus.Message())
		// httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      http.StatusBadRequest,
				Message:   "Registration failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.RegisterUserResponse{
			UserID:       resp.UserID,
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
			ExpiresIn:    resp.ExpiresIn,
			UserProfile:  mapUserProfileHelper(resp.UserProfile),
			Message:      resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) LoginUserHandler(c *gin.Context) {
	var req model.LoginUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	loginUserRequest := &authUserAdminPB.LoginUserRequest{
		Email:         req.Email,
		Password:      req.Password,
		TwoFactorCode: req.Code,
		TraceID:       GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.LoginUser(c.Request.Context(), loginUserRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Login failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.LoginUserResponse{
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
			ExpiresIn:    resp.ExpiresIn,
			UserID:       resp.UserID,
			UserProfile:  mapUserProfileHelper(resp.UserProfile),
			Message:      resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) GoogleLoginInitiate(c *gin.Context) {
	url := uc.googleCfg.AuthCodeURL("state", oauth2.AccessTypeOffline)
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]string{"url": url},
		Error:   nil,
	})
}

func (uc *UserController) GoogleLoginCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		// Redirect to frontend with error details
		config := configs.LoadConfig()
		redirectURL := fmt.Sprintf("%s/login?success=false&type=ERR_INVALID_REQUEST&message=Missing code parameter&details=Google OAuth code is required",
			config.FrontendURL)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	token, err := uc.googleCfg.Exchange(c.Request.Context(), code)
	if err != nil {
		// Redirect to frontend with error details
		config := configs.LoadConfig()
		redirectURL := fmt.Sprintf("%s/login?success=false&type=ERR_INVALID_REQUEST&message=Google login failed&details=Google auth failed in exchange",
			config.FrontendURL)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	googleReq := &authUserAdminPB.GoogleLoginRequest{
		IdToken: token.AccessToken,
	}

	resp, err := uc.userClient.LoginWithGoogle(c.Request.Context(), googleReq)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, _, details := parseGrpcError(grpcStatus.Message())

		// Redirect to frontend with error details
		config := configs.LoadConfig()
		redirectURL := fmt.Sprintf("%s/login?success=false&type=%s&message=Google login failed&details=%s",
			config.FrontendURL, errorType, details)
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	// Redirect the user to the frontend URL with tokens in query parameters
	config := configs.LoadConfig()
	redirectURL := fmt.Sprintf("%s?success=true&accessToken=%s&refreshToken=%s&expiresIn=%d&userID=%s",
		config.FrontendURL,
		resp.AccessToken,
		resp.RefreshToken,
		resp.ExpiresIn,
		resp.UserID,
	)

	c.Redirect(http.StatusFound, redirectURL)
}

func (uc *UserController) LoginAdminHandler(c *gin.Context) {
	var req model.LoginAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	loginAdminRequest := &authUserAdminPB.LoginAdminRequest{
		Email:    req.Email,
		Password: req.Password,
		TraceID:  GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.LoginAdmin(c.Request.Context(), loginAdminRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Admin login failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.LoginAdminResponse{
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
			ExpiresIn:    resp.ExpiresIn,
			AdminID:      resp.AdminID,
			Message:      resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) TokenRefreshHandler(c *gin.Context) {
	var req model.TokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	tokenRefreshRequest := &authUserAdminPB.TokenRefreshRequest{
		RefreshToken: req.RefreshToken,
		TraceID:      GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.TokenRefresh(c.Request.Context(), tokenRefreshRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Token refresh failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.TokenRefreshResponse{
			AccessToken: resp.AccessToken,
			ExpiresIn:   resp.ExpiresIn,
			UserID:      resp.UserID,
			Message:     resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) LogoutUserHandler(c *gin.Context) {
	// userID, _ := c.Get(middleware.EntityIDKey)
	jwtToken, _ := c.Get(middleware.JWTToken)

	// Retrieve the cache from the context
	cacheValue, exists := c.Get("cacheInstance")
	if !exists {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Cache not initialized",
			},
		})
		return
	}
	cacheInstance, ok := cacheValue.(*cache.Cache)
	if !ok {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Invalid cache type",
			},
		})
		return
	}

	cacheInstance.InvalidateToken(jwtToken.(string))

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.LogoutResponse{
			Message: "Logout Successful",
		},
		Error: nil,
	})
}

func (uc *UserController) ResendEmailVerificationHandler(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing email query parameter",
				Details:   "email is required",
			},
		})
		return
	}

	resendEmailVerificationRequest := &authUserAdminPB.ResendEmailVerificationRequest{
		Email:   email,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.ResendEmailVerification(c.Request.Context(), resendEmailVerificationRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Email verification resend failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.ResendEmailVerificationResponse{
			Message:  resp.Message,
			ExpiryAt: resp.ExpiryAt,
		},
		Error: nil,
	})
}

func (uc *UserController) VerifyUserHandler(c *gin.Context) {
	email := c.Query("email")
	token := c.Query("token")
	if email == "" || token == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing email or token query parameter",
				Details:   "email and token are required",
			},
		})
		return
	}

	verifyUserRequest := &authUserAdminPB.VerifyUserRequest{
		Email:   email,
		Token:   token,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.VerifyUser(c.Request.Context(), verifyUserRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Verification failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.VerifyUserResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) ForgotPasswordHandler(c *gin.Context) {
	var req model.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}
	if req.Email == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing email query parameter",
				Details:   "email is required",
			},
		})
		return
	}

	forgotPasswordRequest := &authUserAdminPB.ForgotPasswordRequest{
		Email:   req.Email,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.ForgotPassword(c.Request.Context(), forgotPasswordRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Password recovery failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.ForgotPasswordResponse{
			Message: resp.Message,
			Token:   resp.Token,
		},
		Error: nil,
	})
}

func (uc *UserController) FinishForgotPasswordHandler(c *gin.Context) {
	var req model.FinishForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	finishForgotPasswordRequest := &authUserAdminPB.FinishForgotPasswordRequest{
		Email:           req.Email,
		Token:           req.Token,
		NewPassword:     req.NewPassword,
		ConfirmPassword: req.ConfirmPassword,
		TraceID:         GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.FinishForgotPassword(c.Request.Context(), finishForgotPasswordRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Password reset failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.FinishForgotPasswordResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) ChangePasswordHandler(c *gin.Context) {
	var req model.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	userID, _ := c.Get(middleware.EntityIDKey)

	if req.OldPassword == req.NewPassword || req.NewPassword != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PW_CHANGE_MISMATCH,
				Code:      http.StatusBadRequest,
				Message:   "Password mismatch",
				Details:   "old password, new password, and confirm password must be different",
			},
		})
		return
	}

	changePasswordRequest := &authUserAdminPB.ChangePasswordRequest{
		UserID:          userID.(string),
		OldPassword:     req.OldPassword,
		NewPassword:     req.NewPassword,
		ConfirmPassword: req.ConfirmPassword,
		TraceID:         GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.ChangePassword(c.Request.Context(), changePasswordRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Password change failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.ChangePasswordResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

// User Management
func (uc *UserController) UpdateProfileHandler(c *gin.Context) {
	var req model.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	userID, exists := c.Get(middleware.EntityIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_UNAUTHORIZED,
				Code:      http.StatusUnauthorized,
				Message:   "Failed to get user ID",
				Details:   "userID is required",
			},
		})
		return
	}

	updateProfileRequest := &authUserAdminPB.UpdateProfileRequest{
		UserID:            userID.(string),
		UserName:          req.UserName,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Country:           req.Country,
		Bio:               req.Bio,
		PrimaryLanguageID: req.PrimaryLanguageID,
		MuteNotifications: req.MuteNotifications,
		Socials: &authUserAdminPB.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
		TraceID: GetTraceID(&c.Request.Header),
	}

	var forceChangeCountryLeaderboard bool
	if req.Country != "" {
		forceChangeCountryLeaderboard = true
	}

	resp, err := uc.userClient.UpdateProfile(c.Request.Context(), updateProfileRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Profile update failed",
				Details:   details,
			},
		})
		return
	}

	if forceChangeCountryLeaderboard {
		uc.problemClient.ForceChangeUserEntityInSubmission(context.Background(), &problemPB.ForceChangeUserEntityInSubmissionRequest{
			Entity: req.Country,
			UserId: userID.(string),
		})
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.UpdateProfileResponse{
			Message:     resp.Message,
			UserProfile: mapUserProfileHelper(resp.UserProfile),
		},
		Error: nil,
	})
}

func (uc *UserController) UpdateProfileImageHandler(c *gin.Context) {
	// var req model.UpdateProfileImageRequest
	file, err := c.FormFile("avatar")

	if err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	userID, exists := c.Get(middleware.EntityIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_UNAUTHORIZED,
				Code:      http.StatusUnauthorized,
				Message:   "Failed to get user ID",
				Details:   "userID is required",
			},
		})
		return
	}

	avatarUrl, _ := utils.UploadToCloudinary(file)

	updateProfileImageRequest := &authUserAdminPB.UpdateProfileImageRequest{
		UserID:    userID.(string),
		AvatarURL: avatarUrl,
		TraceID:   GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.UpdateProfileImage(c.Request.Context(), updateProfileImageRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Image update failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.UpdateProfileImageResponse{
			Message:   resp.Message,
			AvatarURL: resp.AvatarURL,
		},
		Error: nil,
	})
}

func (uc *UserController) GetUserProfileHandler(c *gin.Context) {
	userID, _ := c.Get(middleware.EntityIDKey)

	fmt.Println("userID ", userID)

	if userID == "" {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_UNAUTHORIZED,
				Code:      http.StatusUnauthorized,
				Message:   "Failed to get user ID from context",
				Details:   "userID is required",
			},
		})
		return
	}

	getUserProfileRequest := &authUserAdminPB.GetUserProfileRequest{
		UserID:  userID.(string),
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.GetUserProfile(c.Request.Context(), getUserProfileRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Profile retrieval failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.GetUserProfileResponse{
			UserProfile: mapUserProfileHelper(resp.UserProfile),
			Message:     resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) GetUserProfilePublicHandler(c *gin.Context) {
	userNameparams := c.Query("username")
	userIDparams := c.Query("userid")

	fmt.Println("useridparam ", userIDparams)
	fmt.Println("usernameparam ", userNameparams)

	if userNameparams == "" && userIDparams == "" {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_UNAUTHORIZED,
				Code:      http.StatusUnauthorized,
				Message:   "Failed to get user name from query",
				Details:   "username is required",
			},
		})
		return
	}

	getUserProfileRequest := &authUserAdminPB.GetUserProfileRequest{
		UserID:   userIDparams,
		UserName: &userNameparams,
		TraceID:  GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.GetUserProfile(c.Request.Context(), getUserProfileRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Profile retrieval failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.GetUserProfileResponse{
			UserProfile: mapUserProfileHelper(resp.UserProfile),
			Message:     resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) CheckBanStatusHandler(c *gin.Context) {
	var req model.CheckBanStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	checkBanStatusRequest := &authUserAdminPB.CheckBanStatusRequest{
		UserID:  req.UserID,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.CheckBanStatus(c.Request.Context(), checkBanStatusRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Ban status check failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.CheckBanStatusResponse{
			IsBanned:      resp.IsBanned,
			Reason:        resp.Reason,
			BanExpiration: resp.BanExpiration,
			Message:       resp.Message,
		},
		Error: nil,
	})
}

// Social Features
func (uc *UserController) FollowUserHandler(c *gin.Context) {
	followUserID := c.Query("followeeID")
	fmt.Println("followUserID ", followUserID)
	if followUserID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing userID query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	userID, exists := c.Get(middleware.EntityIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_UNAUTHORIZED,
				Code:      http.StatusUnauthorized,
				Message:   "Failed to get user ID from context",
				Details:   "userID is required",
			},
		})
		return
	}

	followUserRequest := &authUserAdminPB.FollowUserRequest{
		FolloweeID: followUserID,
		FollowerID: userID.(string),
		TraceID:    GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.FollowUser(c.Request.Context(), followUserRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Follow failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.FollowUserResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) UnfollowUserHandler(c *gin.Context) {
	unfollowUserID := c.Query("unfollowUserID")
	if unfollowUserID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing userID query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	userID, exists := c.Get(middleware.EntityIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_UNAUTHORIZED,
				Code:      http.StatusUnauthorized,
				Message:   "Failed to get user ID from context",
				Details:   "userID is required",
			},
		})
		return
	}

	unfollowUserRequest := &authUserAdminPB.UnfollowUserRequest{
		FolloweeID: unfollowUserID,
		FollowerID: userID.(string),
		TraceID:    GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.UnfollowUser(c.Request.Context(), unfollowUserRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Unfollow failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.UnfollowUserResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) GetFollowingHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		if jwtUserID, exists := c.Get(middleware.EntityIDKey); exists {
			userID = jwtUserID.(string)
		} else {
			c.JSON(http.StatusBadRequest, model.GenericResponse{
				Success: false,
				Status:  http.StatusBadRequest,
				Payload: nil,
				Error: &model.ErrorInfo{
					ErrorType: customerrors.ERR_PARAM_EMPTY,
					Code:      http.StatusBadRequest,
					Message:   "Missing userID query parameter",
					Details:   "userID is required",
				},
			})
			return
		}
	}

	getFollowingRequest := &authUserAdminPB.GetFollowingRequest{
		UserID:  userID,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.GetFollowing(c.Request.Context(), getFollowingRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Get following failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.GetFollowingResponse{
			Users:         mapUserProfiles(resp.Users),
			TotalCount:    resp.TotalCount,
			NextPageToken: resp.NextPageToken,
			Message:       resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) GetFollowersHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		if jwtUserID, exists := c.Get(middleware.EntityIDKey); exists {
			userID = jwtUserID.(string)
		} else {
			c.JSON(http.StatusBadRequest, model.GenericResponse{
				Success: false,
				Status:  http.StatusBadRequest,
				Payload: nil,
				Error: &model.ErrorInfo{
					ErrorType: customerrors.ERR_PARAM_EMPTY,
					Code:      http.StatusBadRequest,
					Message:   "Missing userID query parameter",
					Details:   "userID is required",
				},
			})
			return
		}
	}

	getFollowersRequest := &authUserAdminPB.GetFollowersRequest{
		UserID:  userID,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.GetFollowers(c.Request.Context(), getFollowersRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Get followers failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.GetFollowersResponse{
			Users:         mapUserProfiles(resp.Users),
			TotalCount:    resp.TotalCount,
			NextPageToken: resp.NextPageToken,
			Message:       resp.Message,
		},
		Error: nil,
	})
}

//

func (uc *UserController) GetFollowFollowingCheckHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {

		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing userID query parameter",
				Details:   "userID is required",
			},
		})
		return

	}

	ownerUserID, _ := c.Get(middleware.EntityIDKey)

	GetFollowFollowingCheckRequest := &authUserAdminPB.GetFollowFollowingCheckRequest{
		TargetUserID: userID,
		OwnerUserID:  ownerUserID.(string),
		TraceID:      GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.GetFollowFollowingCheck(c.Request.Context(), GetFollowFollowingCheckRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Get follow check failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: resp,
		Error:   nil,
	})
}

// Admin Operations
func (uc *UserController) CreateUserAdminHandler(c *gin.Context) {
	var req model.CreateUserAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	createUserAdminRequest := &authUserAdminPB.CreateUserAdminRequest{
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		Role:            req.Role,
		Email:           req.Email,
		AuthType:        req.AuthType,
		Password:        req.Password,
		ConfirmPassword: req.ConfirmPassword,
		TraceID:         GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.CreateUserAdmin(c.Request.Context(), createUserAdminRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "User creation failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.CreateUserAdminResponse{
			UserID:  resp.UserID,
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) UpdateUserAdminHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing userID query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	var req model.UpdateUserAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	updateUserAdminRequest := &authUserAdminPB.UpdateUserAdminRequest{
		UserID:            userID,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Country:           req.Country,
		Role:              req.Role,
		Email:             req.Email,
		Password:          req.Password,
		PrimaryLanguageID: req.PrimaryLanguageID,
		MuteNotifications: req.MuteNotifications,
		Socials: &authUserAdminPB.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.UpdateUserAdmin(c.Request.Context(), updateUserAdminRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "User update failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.UpdateUserAdminResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) BanUserHandler(c *gin.Context) {
	var req model.BanUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	banUserRequest := &authUserAdminPB.BanUserRequest{
		UserID:    req.UserID,
		BanType:   req.BanType,
		BanReason: req.BanReason,
		BanExpiry: req.BanExpiry,
		TraceID:   GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.BanUser(c.Request.Context(), banUserRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, _ := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Ban failed",
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.BanUserResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) UnbanUserHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing userID query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	unbanUserRequest := &authUserAdminPB.UnbanUserRequest{
		UserID:  userID,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.UnbanUser(c.Request.Context(), unbanUserRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Unban failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.UnbanUserResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) VerifyAdminUserHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing userID query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	verifyAdminUserRequest := &authUserAdminPB.VerifyAdminUserRequest{
		UserID:  userID,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.VerifyAdminUser(c.Request.Context(), verifyAdminUserRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Verification failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.VerifyAdminUserResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) UnverifyUserHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing userID query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	unverifyUserRequest := &authUserAdminPB.UnverifyUserAdminRequest{
		UserID:  userID,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.UnverifyUser(c.Request.Context(), unverifyUserRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Unverification failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.UnverifyUserAdminResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) SoftDeleteUserAdminHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing userID query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	softDeleteUserAdminRequest := &authUserAdminPB.SoftDeleteUserAdminRequest{
		UserID:  userID,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.SoftDeleteUserAdmin(c.Request.Context(), softDeleteUserAdminRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Soft delete failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.SoftDeleteUserAdminResponse{
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) GetAllUsersHandler(c *gin.Context) {
	getAllUsersRequest := &authUserAdminPB.GetAllUsersRequest{
		TraceID: GetTraceID(&c.Request.Header),
	}

	//bind and parse params
	var Params struct {
		NextPageToken  string `form:"nextPageToken"`
		PrevPageToken  string `form:"prevPageToken"`
		Limit          int32  `form:"limit"`
		RoleFilter     string `form:"roleFilter"`
		StatusFilter   string `form:"statusFilter"`
		NameFilter     string `form:"nameFilter"`
		EmailFilter    string `form:"emailFilter"`
		FromDateFilter int64  `form:"fromDateFilter"`
		ToDateFilter   int64  `form:"toDateFilter"`
	}

	// fmt.Println("Raw Query:", c.Request.URL.RawQuery)

	if err := c.ShouldBindQuery(&Params); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query params"})
		return
	}

	//conditionally assign fields
	if Params.NextPageToken != "" {
		getAllUsersRequest.NextPageToken = Params.NextPageToken
	}
	if Params.PrevPageToken != "" {
		getAllUsersRequest.PrevPageToken = Params.PrevPageToken
	}
	if Params.Limit != 0 {
		getAllUsersRequest.Limit = Params.Limit
	}
	if Params.RoleFilter != "" {
		getAllUsersRequest.RoleFilter = Params.RoleFilter
	}
	if Params.StatusFilter != "" {
		getAllUsersRequest.StatusFilter = Params.StatusFilter
	}
	if Params.NameFilter != "" {
		getAllUsersRequest.NameFilter = Params.NameFilter
	}
	if Params.EmailFilter != "" {
		getAllUsersRequest.EmailFilter = Params.EmailFilter
	}
	if Params.FromDateFilter != 0 {
		getAllUsersRequest.FromDateFilter = Params.FromDateFilter
	}
	if Params.ToDateFilter != 0 {
		getAllUsersRequest.ToDateFilter = Params.ToDateFilter
	}

	// fmt.Println("getAllUsersRequest ", getAllUsersRequest)
	// fmt.Println("Params ", Params)

	resp, err := uc.userClient.GetAllUsers(c.Request.Context(), getAllUsersRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Get users failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.GetAllUsersResponse{
			Users:         mapUserProfilesforAdmins(resp.Users),
			TotalCount:    resp.TotalCount,
			PrevPageToken: resp.PrevPageToken,
			NextPageToken: resp.NextPageToken,
			Message:       resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) BanHistoryHandler(c *gin.Context) {
	ctxUserID, exists := c.Get(middleware.EntityIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_UNAUTHORIZED,
				Code:      http.StatusUnauthorized,
				Message:   "Failed to get user ID from context",
				Details:   "userID is required",
			},
		})
		return
	}

	userID := c.Query("userID")
	if userID == "" && ctxUserID.(string) == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing userID query parameter",
				Details:   "userID is required",
			},
		})
		return
	}

	if userID == "" {
		userID = ctxUserID.(string)
	}

	banHistoryRequest := &authUserAdminPB.BanHistoryRequest{
		UserID:  userID,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.BanHistory(c.Request.Context(), banHistoryRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Ban history retrieval failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.BanHistoryResponse{
			Bans:    mapBanHistories(resp.Bans),
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) SearchUsersHandler(c *gin.Context) {
	query := c.Query("query")
	pageToken := c.Query("pageToken")
	limitStr := c.Query("limit")

	limit := int32(10)
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = int32(l)
		}
	}

	if query == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing query parameter",
				Details:   "query is required",
			},
		})
		return
	}

	searchUsersRequest := &authUserAdminPB.SearchUsersRequest{
		Query:     query,
		PageToken: pageToken,
		Limit:     limit,
		TraceID:   GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.SearchUsers(c.Request.Context(), searchUsersRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Search users failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.SearchUsersResponse{
			Users:         mapUserProfiles(resp.Users),
			TotalCount:    resp.TotalCount,
			NextPageToken: resp.NextPageToken,
			Message:       resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) SetUpTwoFactorAuthHandler(c *gin.Context) {
	var req model.SetUpTwoFactorAuthRequest
	userID, _ := c.Get(middleware.EntityIDKey)
	req.UserID = userID.(string)
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	setUpTwoFactorAuthRequest := &authUserAdminPB.SetUpTwoFactorAuthRequest{
		UserID:   req.UserID,
		Password: req.Password,
		TraceID:  GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.SetUpTwoFactorAuth(c.Request.Context(), setUpTwoFactorAuthRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Set up two factor auth failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.SetUpTwoFactorAuthResponse{
			Image:   resp.Image,
			Secret:  resp.Secret,
			Message: resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) GetTwoFactorAuthStatusHandler(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_PARAM_EMPTY,
				Code:      http.StatusBadRequest,
				Message:   "Missing email query parameter",
				Details:   "email is required",
			},
		})
		return
	}

	getTwoFactorAuthStatusRequest := &authUserAdminPB.GetTwoFactorAuthStatusRequest{
		Email:   email,
		TraceID: GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.GetTwoFactorAuthStatus(c.Request.Context(), getTwoFactorAuthStatusRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Get two factor auth status failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.GetTwoFactorAuthStatusResponse{
			IsEnabled: resp.IsEnabled,
			Message:   resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) VerifyTwoFactorAuth(c *gin.Context) {
	// get userid from context
	userID, exists := c.Get(middleware.EntityIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_UNAUTHORIZED,
				Code:      http.StatusUnauthorized,
				Message:   "unauthorized",
				Details:   "user not authenticated",
			},
		})
		return
	}

	// parse request
	var req struct {
		TwoFactorCode string `json:"otp" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "invalid request",
				Details:   "two factor code is required",
			},
		})
		return
	}

	// verify code
	verifyRequest := &authUserAdminPB.VerifyTwoFactorAuthRequest{
		UserID:        userID.(string),
		TwoFactorCode: req.TwoFactorCode,
		TraceID:       GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.VerifyTwoFactorAuth(c.Request.Context(), verifyRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "verification failed",
				Details:   details,
			},
		})
		return
	}

	// return success
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"verified": resp.Verified,
			"message":  resp.Message,
		},
		Error: nil,
	})
}

func (uc *UserController) DisableTwoFactorAuthHandler(c *gin.Context) {
	var req model.DisableTwoFactorAuthRequest
	userID, _ := c.Get(middleware.EntityIDKey)
	req.UserID = userID.(string)
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: customerrors.ERR_INVALID_REQUEST,
				Code:      http.StatusBadRequest,
				Message:   "Invalid request",
				Details:   err.Error(),
			},
		})
		return
	}

	deleteTwoFactorAuthRequest := &authUserAdminPB.DisableTwoFactorAuthRequest{
		UserID:   req.UserID,
		Password: req.Password,
		Otp:      req.Otp,
		TraceID:  GetTraceID(&c.Request.Header),
	}

	resp, err := uc.userClient.DisableTwoFactorAuth(c.Request.Context(), deleteTwoFactorAuthRequest)
	if err != nil {
		grpcStatus, _ := status.FromError(err)
		errorType, grpcCode, details := parseGrpcError(grpcStatus.Message())
		httpCode := mapGrpcCodeToHttp(grpcCode)

		c.JSON(httpCode, model.GenericResponse{
			Success: false,
			Status:  httpCode,
			Payload: nil,
			Error: &model.ErrorInfo{
				ErrorType: errorType,
				Code:      httpCode,
				Message:   "Delete two factor auth failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"message": resp.Message,
		},
		Error: nil,
	})
}

// Mapping functions remain unchanged
func mapUserProfileHelper(protoProfile *authUserAdminPB.UserProfile) model.UserProfile {
	if protoProfile == nil {
		return model.UserProfile{}
	}

	// fmt.Println(protoProfile)

	var socials model.Socials
	if protoProfile.Socials != nil {
		socials = model.Socials{
			Github:   protoProfile.Socials.Github,
			Twitter:  protoProfile.Socials.Twitter,
			Linkedin: protoProfile.Socials.Linkedin,
		}
	}

	return model.UserProfile{
		UserID:            protoProfile.UserID,
		UserName:          protoProfile.UserName,
		FirstName:         protoProfile.FirstName,
		LastName:          protoProfile.LastName,
		AvatarURL:         protoProfile.AvatarData,
		IsVerified:        protoProfile.IsVerified,
		Email:             protoProfile.Email,
		Bio:               protoProfile.Bio,
		Role:              protoProfile.Role,
		Country:           protoProfile.Country,
		PrimaryLanguageID: protoProfile.PrimaryLanguageID,
		MuteNotifications: protoProfile.MuteNotifications,
		Socials:           socials,
		CreatedAt:         protoProfile.CreatedAt,
	}
}

func mapUserProfileForAdminsHelper(protoProfile *authUserAdminPB.UserProfile) model.UserProfile {
	if protoProfile == nil {
		return model.UserProfile{}
	}

	var socials model.Socials
	if protoProfile.Socials != nil {
		socials = model.Socials{
			Github:   protoProfile.Socials.Github,
			Twitter:  protoProfile.Socials.Twitter,
			Linkedin: protoProfile.Socials.Linkedin,
		}
	}

	return model.UserProfile{
		UserID:            protoProfile.UserID,
		UserName:          protoProfile.UserName,
		FirstName:         protoProfile.FirstName,
		LastName:          protoProfile.LastName,
		AvatarURL:         protoProfile.AvatarData,
		IsVerified:        protoProfile.IsVerified,
		Email:             protoProfile.Email,
		Bio:               protoProfile.Bio,
		Role:              protoProfile.Role,
		Country:           protoProfile.Country,
		PrimaryLanguageID: protoProfile.PrimaryLanguageID,
		MuteNotifications: protoProfile.MuteNotifications,
		Socials:           socials,
		CreatedAt:         protoProfile.CreatedAt,
		AuthType:          protoProfile.AuthType,
		IsBanned:          protoProfile.IsBanned,
		BanReason:         protoProfile.BanReason,
		BanExpiration:     protoProfile.BanExpiration,
		TwoFactorEnabled:  protoProfile.TwoFactorEnabled,
	}
}

func (uc *UserController) UserAvailable(ctx *gin.Context) {
	username := ctx.Query("username")
	available := false
	if username == "" {
		ctx.JSON(http.StatusNotFound, model.GenericResponse{
			Success: false,
			Status:  http.StatusNotFound,
			Payload: map[string]interface{}{
				"available": available,
			},
			Error: &model.ErrorInfo{
				ErrorType: "NOT_FOUND",
				Code:      http.StatusNotFound,
				Message:   "username not found",
				Details:   "username not found, available for user",
			},
		})

		return
	}

	resp, _ := uc.userClient.UsernameAvailable(ctx.Request.Context(), &authUserAdminPB.UsernameAvailableRequest{
		Username: username,
	})

	fmt.Println(resp)

	if resp.Status {
		available = true
	}

	ctx.JSON(http.StatusOK, model.GenericResponse{
		Success: available,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"available": available,
		},
		Error: &model.ErrorInfo{
			ErrorType: "",
			Code:      http.StatusOK,
			Message:   "",
			Details:   "",
		},
	})

}

func mapUserProfiles(protoProfiles []*authUserAdminPB.UserProfile) []model.UserProfile {
	profiles := make([]model.UserProfile, len(protoProfiles))
	for i, p := range protoProfiles {
		profiles[i] = mapUserProfileHelper(p)
	}
	return profiles
}
func mapUserProfilesforAdmins(protoProfiles []*authUserAdminPB.UserProfile) []model.UserProfile {
	profiles := make([]model.UserProfile, len(protoProfiles))
	for i, p := range protoProfiles {
		profiles[i] = mapUserProfileForAdminsHelper(p)
	}
	return profiles
}

func mapBanHistory(protoBan *authUserAdminPB.BanHistory) model.BanHistory {
	return model.BanHistory{
		ID:        protoBan.Id,
		UserID:    protoBan.UserID,
		BannedAt:  protoBan.BannedAt,
		BanType:   protoBan.BanType,
		BanReason: protoBan.BanReason,
		BanExpiry: protoBan.BanExpiry,
	}
}

func mapBanHistories(protoBans []*authUserAdminPB.BanHistory) []model.BanHistory {
	bans := make([]model.BanHistory, len(protoBans))
	for i, b := range protoBans {
		bans[i] = mapBanHistory(b)
	}
	return bans
}

func GetTraceID(header *http.Header) string {
	TraceID := header.Get("X-Trace-ID")
	// fmt.Println(" TraceID ",TraceID)
	return TraceID
}
