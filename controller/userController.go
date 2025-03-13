package controller

import (
	"net/http"
	"regexp"
	"strconv"

	"xcode/customerrors"
	"xcode/middleware"
	"xcode/model"

	"github.com/gin-gonic/gin"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UserController handles user-related API requests
type UserController struct {
	userClient AuthUserAdminService.AuthUserAdminServiceClient
}

// NewUserController creates a new instance of UserController
func NewUserController(userClient AuthUserAdminService.AuthUserAdminServiceClient) *UserController {
	return &UserController{
		userClient: userClient,
	}
}

// GetUserClient returns the user service client for middleware use
func (uc *UserController) GetUserClient() AuthUserAdminService.AuthUserAdminServiceClient {
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
		return http.StatusInternalServerError
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

	registerUserRequest := &AuthUserAdminService.RegisterUserRequest{
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		Email:           req.Email,
		Password:        req.Password,
		ConfirmPassword: req.ConfirmPassword,
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
			UserProfile:  mapUserProfile(resp.UserProfile),
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

	loginUserRequest := &AuthUserAdminService.LoginUserRequest{
		Email:         req.Email,
		Password:      req.Password,
		TwoFactorCode: req.Code,
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
			UserProfile:  mapUserProfile(resp.UserProfile),
			Message:      resp.Message,
		},
		Error: nil,
	})
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

	loginAdminRequest := &AuthUserAdminService.LoginAdminRequest{
		Email:    req.Email,
		Password: req.Password,
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

	tokenRefreshRequest := &AuthUserAdminService.TokenRefreshRequest{
		RefreshToken: req.RefreshToken,
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
	userID, _ := c.Get(middleware.EntityIDKey)
	jwtToken, _ := c.Get(middleware.JWTToken)

	middleware.RevokeToken(jwtToken.(string))

	logoutRequest := &AuthUserAdminService.LogoutRequest{
		UserID: userID.(string),
	}

	resp, err := uc.userClient.LogoutUser(c.Request.Context(), logoutRequest)
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
				Message:   "Logout failed",
				Details:   details,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.LogoutResponse{
			Message: resp.Message,
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

	resendEmailVerificationRequest := &AuthUserAdminService.ResendEmailVerificationRequest{
		Email: email,
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

	verifyUserRequest := &AuthUserAdminService.VerifyUserRequest{
		Email: email,
		Token: token,
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

	forgotPasswordRequest := &AuthUserAdminService.ForgotPasswordRequest{
		Email: req.Email,
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

	finishForgotPasswordRequest := &AuthUserAdminService.FinishForgotPasswordRequest{
		Email:           req.Email,
		Token:           req.Token,
		NewPassword:     req.NewPassword,
		ConfirmPassword: req.ConfirmPassword,
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

	changePasswordRequest := &AuthUserAdminService.ChangePasswordRequest{
		UserID:          userID.(string),
		OldPassword:     req.OldPassword,
		NewPassword:     req.NewPassword,
		ConfirmPassword: req.ConfirmPassword,
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

	updateProfileRequest := &AuthUserAdminService.UpdateProfileRequest{
		UserID:            userID.(string),
		UserName:          req.UserName,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Country:           req.Country,
		PrimaryLanguageID: req.PrimaryLanguageID,
		MuteNotifications: req.MuteNotifications,
		Socials: &AuthUserAdminService.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
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

	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: model.UpdateProfileResponse{
			Message:     resp.Message,
			UserProfile: mapUserProfile(resp.UserProfile),
		},
		Error: nil,
	})
}

func (uc *UserController) UpdateProfileImageHandler(c *gin.Context) {
	var req model.UpdateProfileImageRequest
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

	updateProfileImageRequest := &AuthUserAdminService.UpdateProfileImageRequest{
		UserID:    userID.(string),
		AvatarURL: req.AvatarURL,
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

	getUserProfileRequest := &AuthUserAdminService.GetUserProfileRequest{
		UserID: userID.(string),
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
			UserProfile: mapUserProfile(resp.UserProfile),
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

	checkBanStatusRequest := &AuthUserAdminService.CheckBanStatusRequest{
		UserID: req.UserID,
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
	followUserID := c.Query("followUserID")
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

	followUserRequest := &AuthUserAdminService.FollowUserRequest{
		FolloweeID: followUserID,
		FollowerID: userID.(string),
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

	unfollowUserRequest := &AuthUserAdminService.UnfollowUserRequest{
		FolloweeID: unfollowUserID,
		FollowerID: userID.(string),
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

	getFollowingRequest := &AuthUserAdminService.GetFollowingRequest{
		UserID: userID,
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

	getFollowersRequest := &AuthUserAdminService.GetFollowersRequest{
		UserID: userID,
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

	createUserAdminRequest := &AuthUserAdminService.CreateUserAdminRequest{
		FirstName:       req.FirstName,
		LastName:        req.LastName,
		Role:            req.Role,
		Email:           req.Email,
		AuthType:        req.AuthType,
		Password:        req.Password,
		ConfirmPassword: req.ConfirmPassword,
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

	updateUserAdminRequest := &AuthUserAdminService.UpdateUserAdminRequest{
		UserID:            userID,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		Country:           req.Country,
		Role:              req.Role,
		Email:             req.Email,
		Password:          req.Password,
		PrimaryLanguageID: req.PrimaryLanguageID,
		MuteNotifications: req.MuteNotifications,
		Socials: &AuthUserAdminService.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
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

	banUserRequest := &AuthUserAdminService.BanUserRequest{
		UserID:    req.UserID,
		BanType:   req.BanType,
		BanReason: req.BanReason,
		BanExpiry: req.BanExpiry,
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

	unbanUserRequest := &AuthUserAdminService.UnbanUserRequest{
		UserID: userID,
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

	verifyAdminUserRequest := &AuthUserAdminService.VerifyAdminUserRequest{
		UserID: userID,
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

	unverifyUserRequest := &AuthUserAdminService.UnverifyUserAdminRequest{
		UserID: userID,
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

	softDeleteUserAdminRequest := &AuthUserAdminService.SoftDeleteUserAdminRequest{
		UserID: userID,
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
	getAllUsersRequest := &AuthUserAdminService.GetAllUsersRequest{}

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
			Users:         mapUserProfiles(resp.Users),
			TotalCount:    resp.TotalCount,
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

	banHistoryRequest := &AuthUserAdminService.BanHistoryRequest{
		UserID: userID,
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

	searchUsersRequest := &AuthUserAdminService.SearchUsersRequest{
		Query:     query,
		PageToken: pageToken,
		Limit:     limit,
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

	setUpTwoFactorAuthRequest := &AuthUserAdminService.SetUpTwoFactorAuthRequest{
		UserID:   req.UserID,
		Password: req.Password,
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

	getTwoFactorAuthStatusRequest := &AuthUserAdminService.GetTwoFactorAuthStatusRequest{
		Email: email,
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

	deleteTwoFactorAuthRequest := &AuthUserAdminService.DisableTwoFactorAuthRequest{
		UserID:   req.UserID,
		Password: req.Password,
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
func mapUserProfile(protoProfile *AuthUserAdminService.UserProfile) model.UserProfile {
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
		Email:             protoProfile.Email,
		Role:              protoProfile.Role,
		Country:           protoProfile.Country,
		PrimaryLanguageID: protoProfile.PrimaryLanguageID,
		MuteNotifications: protoProfile.MuteNotifications,
		Socials:           socials,
		CreatedAt:         protoProfile.CreatedAt,
	}
}

func mapUserProfiles(protoProfiles []*AuthUserAdminService.UserProfile) []model.UserProfile {
	profiles := make([]model.UserProfile, len(protoProfiles))
	for i, p := range protoProfiles {
		profiles[i] = mapUserProfile(p)
	}
	return profiles
}

func mapBanHistory(protoBan *AuthUserAdminService.BanHistory) model.BanHistory {
	return model.BanHistory{
		ID:        protoBan.Id,
		UserID:    protoBan.UserID,
		BannedAt:  protoBan.BannedAt,
		BanType:   protoBan.BanType,
		BanReason: protoBan.BanReason,
		BanExpiry: protoBan.BanExpiry,
	}
}

func mapBanHistories(protoBans []*AuthUserAdminService.BanHistory) []model.BanHistory {
	bans := make([]model.BanHistory, len(protoBans))
	for i, b := range protoBans {
		bans[i] = mapBanHistory(b)
	}
	return bans
}
