package controller

import (
	"net/http"

	"xcode/middleware"
	"xcode/model"

	"github.com/gin-gonic/gin"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
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

// Authentication and Security

func (uc *UserController) RegisterUserHandler(c *gin.Context) {
	var req model.RegisterUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	registerUserRequest := &AuthUserAdminService.RegisterUserRequest{
		FirstName:           req.FirstName,
		LastName:            req.LastName,
		Country:             req.Country,
		Role:                req.Role,
		PrimaryLanguageID:   req.PrimaryLanguageID,
		SecondaryLanguageID: req.SecondaryLanguageID,
		Email:               req.Email,
		AuthType:            req.AuthType,
		Password:            req.Password,
		ConfirmPassword:     req.ConfirmPassword,
		MuteNotifications:   req.MuteNotifications,
		Socials: &AuthUserAdminService.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
	}

	resp, err := uc.userClient.RegisterUser(c.Request.Context(), registerUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Registration failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"userID":  resp.UserID,
			"message": resp.Message,
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
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	loginUserRequest := &AuthUserAdminService.LoginUserRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := uc.userClient.LoginUser(c.Request.Context(), loginUserRequest)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusUnauthorized,
				Message: "Login failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"refreshToken": resp.RefreshToken,
			"expiresIn":    resp.ExpiresIn,
			"userID":       resp.UserID,
			"message":      resp.Message,
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
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
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
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusUnauthorized,
				Message: "Admin login failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"refreshToken": resp.RefreshToken,
			"expiresIn":    resp.ExpiresIn,
			"adminID":      resp.AdminID,
			"message":      resp.Message,
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
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	tokenRefreshRequest := &AuthUserAdminService.TokenRefreshRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := uc.userClient.TokenRefresh(c.Request.Context(), tokenRefreshRequest)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.GenericResponse{
			Success: false,
			Status:  http.StatusUnauthorized,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusUnauthorized,
				Message: "Token refresh failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"accessToken": resp.AccessToken,
			"expiresIn":   resp.ExpiresIn,
			"userID":      resp.UserID,
		},
		Error: nil,
	})
}

func (uc *UserController) LogoutUserHandler(c *gin.Context) {
	var req model.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	logoutRequest := &AuthUserAdminService.LogoutRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.LogoutUser(c.Request.Context(), logoutRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Logout failed",
				Details: err.Error(),
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

func (uc *UserController) ResendOTPHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing userID query parameter",
				Details: "userID is required",
			},
		})
		return
	}

	resendOTPRequest := &AuthUserAdminService.ResendOTPRequest{
		UserID: userID,
	}

	resp, err := uc.userClient.ResendOTP(c.Request.Context(), resendOTPRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "OTP resend failed",
				Details: err.Error(),
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

func (uc *UserController) VerifyUserHandler(c *gin.Context) {
	email := c.Query("email")
	token := c.Query("token")
	if email == "" || token == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing userID or token query parameter",
				Details: "userID and token are required",
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
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Verification failed",
				Details: err.Error(),
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

func (uc *UserController) SetTwoFactorAuthHandler(c *gin.Context) {
	var req model.SetTwoFactorAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	setTwoFactorAuthRequest := &AuthUserAdminService.SetTwoFactorAuthRequest{
		UserID: req.UserID,
		Enable: req.Enable,
	}

	resp, err := uc.userClient.SetTwoFactorAuth(c.Request.Context(), setTwoFactorAuthRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "2FA setup failed",
				Details: err.Error(),
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

func (uc *UserController) ForgotPasswordHandler(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing email query parameter",
				Details: "email is required",
			},
		})
		return
	}

	forgotPasswordRequest := &AuthUserAdminService.ForgotPasswordRequest{
		Email: email,
	}

	resp, err := uc.userClient.ForgotPassword(c.Request.Context(), forgotPasswordRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Password recovery failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"message": resp.Message,
			"token":   resp.Token,
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
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	finishForgotPasswordRequest := &AuthUserAdminService.FinishForgotPasswordRequest{
		UserID:          req.UserID,
		Token:           req.Token,
		NewPassword:     req.NewPassword,
		ConfirmPassword: req.ConfirmPassword,
	}

	resp, err := uc.userClient.FinishForgotPassword(c.Request.Context(), finishForgotPasswordRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Password reset failed",
				Details: err.Error(),
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

func (uc *UserController) ChangePasswordHandler(c *gin.Context) {
	var req model.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	changePasswordRequest := &AuthUserAdminService.ChangePasswordRequest{
		UserID:          req.UserID,
		OldPassword:     req.OldPassword,
		NewPassword:     req.NewPassword,
		ConfirmPassword: req.ConfirmPassword,
	}

	resp, err := uc.userClient.ChangePassword(c.Request.Context(), changePasswordRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Password change failed",
				Details: err.Error(),
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

// User Management

func (uc *UserController) UpdateProfileHandler(c *gin.Context) {
	var req model.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	updateProfileRequest := &AuthUserAdminService.UpdateProfileRequest{
		UserID:              req.UserID,
		FirstName:           req.FirstName,
		LastName:            req.LastName,
		Country:             req.Country,
		PrimaryLanguageID:   req.PrimaryLanguageID,
		SecondaryLanguageID: req.SecondaryLanguageID,
		MuteNotifications:   req.MuteNotifications,
		Socials: &AuthUserAdminService.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
	}

	resp, err := uc.userClient.UpdateProfile(c.Request.Context(), updateProfileRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Profile update failed",
				Details: err.Error(),
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

func (uc *UserController) UpdateProfileImageHandler(c *gin.Context) {
	var req model.UpdateProfileImageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	updateProfileImageRequest := &AuthUserAdminService.UpdateProfileImageRequest{
		UserID:    req.UserID,
		AvatarURL: req.AvatarURL,
	}

	resp, err := uc.userClient.UpdateProfileImage(c.Request.Context(), updateProfileImageRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Image update failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"message":   resp.Message,
			"avatarURL": resp.AvatarURL,
		},
		Error: nil,
	})
}

func (uc *UserController) GetUserProfileHandler(c *gin.Context) {
	userID, exists := c.Get(middleware.EntityIDKey)
	if !exists {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Failed to get user ID from context",
				Details: "userID is required",
			},
		})
		return
	}

	getUserProfileRequest := &AuthUserAdminService.GetUserProfileRequest{
		UserID: userID.(string),
	}

	resp, err := uc.userClient.GetUserProfile(c.Request.Context(), getUserProfileRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Profile retrieval failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"firstName": resp.FirstName,
			"lastName":  resp.LastName,
			"country":   resp.Country,
			"email":     resp.Email,
			"role":      resp.Role,
			"socials": map[string]string{
				"github":   resp.Socials.Github,
				"twitter":  resp.Socials.Twitter,
				"linkedin": resp.Socials.Linkedin,
			},
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
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	checkBanStatusRequest := &AuthUserAdminService.CheckBanStatusRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.CheckBanStatus(c.Request.Context(), checkBanStatusRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Ban status check failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"isBanned":      resp.IsBanned,
			"reason":        resp.Reason,
			"banExpiration": resp.BanExpiration,
			"message":       resp.Message,
		},
		Error: nil,
	})
}

// Social Features

func (uc *UserController) FollowUserHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing userID query parameter",
				Details: "userID is required",
			},
		})
		return
	}

	followUserRequest := &AuthUserAdminService.FollowUserRequest{
		UserID: userID,
	}

	resp, err := uc.userClient.FollowUser(c.Request.Context(), followUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Follow failed",
				Details: err.Error(),
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

func (uc *UserController) UnfollowUserHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing userID query parameter",
				Details: "userID is required",
			},
		})
		return
	}

	unfollowUserRequest := &AuthUserAdminService.UnfollowUserRequest{
		UserID: userID,
	}

	resp, err := uc.userClient.UnfollowUser(c.Request.Context(), unfollowUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Unfollow failed",
				Details: err.Error(),
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

func (uc *UserController) GetFollowingHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		// Fall back to JWT userID if available
		if jwtUserID, exists := c.Get("userID"); exists {
			userID = jwtUserID.(string)
		} else {
			c.JSON(http.StatusBadRequest, model.GenericResponse{
				Success: false,
				Status:  http.StatusBadRequest,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusBadRequest,
					Message: "Missing userID query parameter",
					Details: "userID is required",
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
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Get following failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"data": func() []map[string]interface{} {
				var data []map[string]interface{}
				for _, profile := range resp.Data {
					data = append(data, map[string]interface{}{
						"userID":    profile.UserID,
						"firstName": profile.FirstName,
						"lastName":  profile.LastName,
						"email":     profile.Email,
						"role":      profile.Role,
						"status":    profile.Status,
						"socials": map[string]string{
							"github":   profile.Socials.Github,
							"twitter":  profile.Socials.Twitter,
							"linkedin": profile.Socials.Linkedin,
						},
					})
				}
				return data
			}(),
		},
		Error: nil,
	})
}

func (uc *UserController) GetFollowersHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		// Fall back to JWT userID if available
		if jwtUserID, exists := c.Get("userID"); exists {
			userID = jwtUserID.(string)
		} else {
			c.JSON(http.StatusBadRequest, model.GenericResponse{
				Success: false,
				Status:  http.StatusBadRequest,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusBadRequest,
					Message: "Missing userID query parameter",
					Details: "userID is required",
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
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Get followers failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"data": func() []map[string]interface{} {
				var data []map[string]interface{}
				for _, profile := range resp.Data {
					data = append(data, map[string]interface{}{
						"userID":    profile.UserID,
						"firstName": profile.FirstName,
						"lastName":  profile.LastName,
						"email":     profile.Email,
						"role":      profile.Role,
						"status":    profile.Status,
						"socials": map[string]string{
							"github":   profile.Socials.Github,
							"twitter":  profile.Socials.Twitter,
							"linkedin": profile.Socials.Linkedin,
						},
					})
				}
				return data
			}(),
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
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	createUserAdminRequest := &AuthUserAdminService.CreateUserAdminRequest{
		FirstName:           req.FirstName,
		LastName:            req.LastName,
		Country:             req.Country,
		Role:                req.Role,
		PrimaryLanguageID:   req.PrimaryLanguageID,
		SecondaryLanguageID: req.SecondaryLanguageID,
		Email:               req.Email,
		AuthType:            req.AuthType,
		Password:            req.Password,
		ConfirmPassword:     req.ConfirmPassword,
		MuteNotifications:   req.MuteNotifications,
		Socials: &AuthUserAdminService.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
	}

	resp, err := uc.userClient.CreateUserAdmin(c.Request.Context(), createUserAdminRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "User creation failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"userID":  resp.UserID,
			"message": resp.Message,
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
				Code:    http.StatusBadRequest,
				Message: "Missing userID query parameter",
				Details: "userID is required",
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
				Code:    http.StatusBadRequest,
				Message: "Invalid request",
				Details: err.Error(),
			},
		})
		return
	}

	updateUserAdminRequest := &AuthUserAdminService.UpdateUserAdminRequest{
		UserID:              userID,
		FirstName:           req.FirstName,
		LastName:            req.LastName,
		Country:             req.Country,
		Role:                req.Role,
		Email:               req.Email,
		Password:            req.Password,
		PrimaryLanguageID:   req.PrimaryLanguageID,
		SecondaryLanguageID: req.SecondaryLanguageID,
		MuteNotifications:   req.MuteNotifications,
		Socials: &AuthUserAdminService.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
	}

	resp, err := uc.userClient.UpdateUserAdmin(c.Request.Context(), updateUserAdminRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "User update failed",
				Details: err.Error(),
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

func (uc *UserController) BlockUserHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing userID query parameter",
				Details: "userID is required",
			},
		})
		return
	}

	blockUserRequest := &AuthUserAdminService.BlockUserRequest{
		UserID: userID,
	}

	resp, err := uc.userClient.BlockUser(c.Request.Context(), blockUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Block failed",
				Details: err.Error(),
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

func (uc *UserController) UnblockUserHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing userID query parameter",
				Details: "userID is required",
			},
		})
		return
	}

	unblockUserRequest := &AuthUserAdminService.UnblockUserAdminRequest{
		UserID: userID,
	}

	resp, err := uc.userClient.UnblockUser(c.Request.Context(), unblockUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Unblock failed",
				Details: err.Error(),
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

func (uc *UserController) VerifyAdminUserHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing userID query parameter",
				Details: "userID is required",
			},
		})
		return
	}

	verifyAdminUserRequest := &AuthUserAdminService.VerifyAdminUserRequest{
		UserID: userID,
	}

	resp, err := uc.userClient.VerifyAdminUser(c.Request.Context(), verifyAdminUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Verification failed",
				Details: err.Error(),
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

func (uc *UserController) UnverifyUserHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing userID query parameter",
				Details: "userID is required",
			},
		})
		return
	}

	unverifyUserRequest := &AuthUserAdminService.UnverifyUserAdminRequest{
		UserID: userID,
	}

	resp, err := uc.userClient.UnverifyUser(c.Request.Context(), unverifyUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Unverification failed",
				Details: err.Error(),
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

func (uc *UserController) SoftDeleteUserAdminHandler(c *gin.Context) {
	userID := c.Query("userID")
	if userID == "" {
		c.JSON(http.StatusBadRequest, model.GenericResponse{
			Success: false,
			Status:  http.StatusBadRequest,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusBadRequest,
				Message: "Missing userID query parameter",
				Details: "userID is required",
			},
		})
		return
	}

	softDeleteUserAdminRequest := &AuthUserAdminService.SoftDeleteUserAdminRequest{
		UserID: userID,
	}

	resp, err := uc.userClient.SoftDeleteUserAdmin(c.Request.Context(), softDeleteUserAdminRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Soft delete failed",
				Details: err.Error(),
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

func (uc *UserController) GetAllUsersHandler(c *gin.Context) {


	getAllUsersRequest := &AuthUserAdminService.GetAllUsersRequest{
		
	}

	resp, err := uc.userClient.GetAllUsers(c.Request.Context(), getAllUsersRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.GenericResponse{
			Success: false,
			Status:  http.StatusInternalServerError,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusInternalServerError,
				Message: "Get users failed",
				Details: err.Error(),
			},
		})
		return
	}
	c.JSON(http.StatusOK, model.GenericResponse{
		Success: true,
		Status:  http.StatusOK,
		Payload: map[string]interface{}{
			"users": func() []map[string]interface{} {
				var users []map[string]interface{}
				for _, profile := range resp.Users {
					users = append(users, map[string]interface{}{
						"userID":    profile.UserID,
						"firstName": profile.FirstName,
						"lastName":  profile.LastName,
						"email":     profile.Email,
						"role":      profile.Role,
						"status":    profile.Status,
						"socials": map[string]string{
							"github":   profile.Socials.Github,
							"twitter":  profile.Socials.Twitter,
							"linkedin": profile.Socials.Linkedin,
						},
					})
				}
				return users
			}(),
			"totalCount": resp.TotalCount,
			"message":    resp.Message,
		},
		Error: nil,
	})
}
