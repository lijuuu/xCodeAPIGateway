package controller

import (
    "net/http"
    "strconv"

    "xcode/middleware"
    "xcode/model"

    AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"

    "github.com/gin-gonic/gin"
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

    // Validate Socials
    if req.Socials.Github == "" && req.Socials.Twitter == "" && req.Socials.Linkedin == "" {
        c.JSON(http.StatusBadRequest, model.GenericResponse{
            Success: false,
            Status:  http.StatusBadRequest,
            Payload: nil,
            Error: &model.ErrorInfo{
                Code:    http.StatusBadRequest,
                Message: "At least one social link is required",
            },
        })
        return
    }

    registerUserRequest := &AuthUserAdminService.RegisterUserRequest{
        FirstName:         req.FirstName,
        LastName:          req.LastName,
        Country:           req.Country,
        Role:              req.Role,
        PrimaryLanguageID: req.PrimaryLanguageID,
        Email:             req.Email,
        AuthType:          req.AuthType,
        Password:          req.Password,
        ConfirmPassword:   req.ConfirmPassword,
        MuteNotifications: req.MuteNotifications,
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
        Payload: model.LogoutResponse{
            Message: resp.Message,
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
        Payload: model.ResendOTPResponse{
            Message: resp.Message,
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
                Message: "Missing email or token query parameter",
                Details: "email and token are required",
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
        Payload: model.VerifyUserResponse{
            Message: resp.Message,
        },
        Error: nil,
    })
}

func (uc *UserController) SetTwoFactorAuthHandler(c *gin.Context) {
    var req model.ToggleTwoFactorAuthRequest
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

    setTwoFactorAuthRequest := &AuthUserAdminService.ToggleTwoFactorAuthRequest{
        UserID:        req.UserID,
        TwoFactorAuth: req.TwoFactorAuth,
    }

    resp, err := uc.userClient.ToggleTwoFactorAuth(c.Request.Context(), setTwoFactorAuthRequest)
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
        Payload: model.ToggleTwoFactorAuthResponse{
            Message: resp.Message,
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
                Code:    http.StatusBadRequest,
                Message: "Invalid request",
                Details: err.Error(),
            },
        })
        return
    }

    updateProfileRequest := &AuthUserAdminService.UpdateProfileRequest{
        UserID:            req.UserID,
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
                Code:    http.StatusUnauthorized,
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
                Code:    http.StatusBadRequest,
                Message: "Missing userID query parameter",
                Details: "userID is required",
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
                Code:    http.StatusUnauthorized,
                Message: "Failed to get user ID from context",
                Details: "userID is required",
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
                Code:    http.StatusBadRequest,
                Message: "Missing userID query parameter",
                Details: "userID is required",
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
                Code:    http.StatusUnauthorized,
                Message: "Failed to get user ID from context",
                Details: "userID is required",
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
        Payload: model.UnfollowUserResponse{
            Message: resp.Message,
        },
        Error: nil,
    })
}

func (uc *UserController) GetFollowingHandler(c *gin.Context) {
    userID := c.Query("userID")
    if userID == "" {
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
                Code:    http.StatusBadRequest,
                Message: "Invalid request",
                Details: err.Error(),
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
                Code:    http.StatusBadRequest,
                Message: "Missing userID query parameter",
                Details: "userID is required",
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
        c.JSON(http.StatusInternalServerError, model.GenericResponse{
            Success: false,
            Status:  http.StatusInternalServerError,
            Payload: nil,
            Error: &model.ErrorInfo{
                Code:    http.StatusInternalServerError,
                Message: "Ban failed",
                Details: err.Error(),
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
                Code:    http.StatusBadRequest,
                Message: "Missing userID query parameter",
                Details: "userID is required",
            },
        })
        return
    }

    unbanUserRequest := &AuthUserAdminService.UnbanUserRequest{
        UserID: userID,
    }

    resp, err := uc.userClient.UnbanUser(c.Request.Context(), unbanUserRequest)
    if err != nil {
        c.JSON(http.StatusInternalServerError, model.GenericResponse{
            Success: false,
            Status:  http.StatusInternalServerError,
            Payload: nil,
            Error: &model.ErrorInfo{
                Code:    http.StatusInternalServerError,
                Message: "Unban failed",
                Details: err.Error(),
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
                Code:    http.StatusUnauthorized,
                Message: "Failed to get user ID from context",
                Details: "userID is required",
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
                Code:    http.StatusBadRequest,
                Message: "Missing userID query parameter",
                Details: "userID is required",
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
        c.JSON(http.StatusInternalServerError, model.GenericResponse{
            Success: false,
            Status:  http.StatusInternalServerError,
            Payload: nil,
            Error: &model.ErrorInfo{
                Code:    http.StatusInternalServerError,
                Message: "Ban history retrieval failed",
                Details: err.Error(),
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
                Code:    http.StatusBadRequest,
                Message: "Missing query parameter",
                Details: "query is required",
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
        c.JSON(http.StatusInternalServerError, model.GenericResponse{
            Success: false,
            Status:  http.StatusInternalServerError,
            Payload: nil,
            Error: &model.ErrorInfo{
                Code:    http.StatusInternalServerError,
                Message: "Search users failed",
                Details: err.Error(),
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


// mapUserProfile converts a proto UserProfile to model.UserProfile
func mapUserProfile(protoProfile *AuthUserAdminService.UserProfile) model.UserProfile {
    if protoProfile == nil {
        return model.UserProfile{}
    }
    return model.UserProfile{
        UserID:            protoProfile.UserID,
        UserName:          protoProfile.UserName,
        FirstName:         protoProfile.FirstName,
        LastName:          protoProfile.LastName,
        AvatarURL:         protoProfile.AvatarURL,
        Email:             protoProfile.Email,
        Role:              protoProfile.Role,
        Status:            protoProfile.Status,
        Country:           protoProfile.Country,
        IsBanned:          protoProfile.IsBanned,
        PrimaryLanguageID: protoProfile.PrimaryLanguageID,
        MuteNotifications: protoProfile.MuteNotifications,
        Socials: model.Socials{
            Github:   protoProfile.Socials.Github,
            Twitter:  protoProfile.Socials.Twitter,
            Linkedin: protoProfile.Socials.Linkedin,
        },
        CreatedAt: protoProfile.CreatedAt,
    }
}

// mapUserProfiles converts a slice of proto UserProfile to a slice of model.UserProfile
func mapUserProfiles(protoProfiles []*AuthUserAdminService.UserProfile) []model.UserProfile {
    profiles := make([]model.UserProfile, len(protoProfiles))
    for i, p := range protoProfiles {
        profiles[i] = mapUserProfile(p)
    }
    return profiles
}

// mapBanHistory converts a proto BanHistory to model.BanHistory
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

// mapBanHistories converts a slice of proto BanHistory to a slice of model.BanHistory
func mapBanHistories(protoBans []*AuthUserAdminService.BanHistory) []model.BanHistory {
    bans := make([]model.BanHistory, len(protoBans))
    for i, b := range protoBans {
        bans[i] = mapBanHistory(b)
    }
    return bans
}