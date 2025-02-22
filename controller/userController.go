package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"xcode/model"                           // Assuming your model package is here
	user "github.com/lijuuu/GlobalProtoXcode/UserService"
)

// UserController handles user-related API requests
type UserController struct {
	userClient user.UserServiceClient // No pointer since it’s an interface
}

// NewUserController creates a new instance of UserController
func NewUserController(userClient user.UserServiceClient) *UserController {
	return &UserController{
		userClient: userClient,
	}
}

// GetUserClient returns the user service client for middleware use
func (uc *UserController) GetUserClient() user.UserServiceClient {
	return uc.userClient
}

// Authentication and Security

func (uc *UserController) RegisterUserHandler(c *gin.Context) {
	var req model.RegisterUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	registerUserRequest := &user.RegisterUserRequest{
		FirstName:          req.FirstName,
		LastName:           req.LastName,
		Country:            req.Country,
		Role:               req.Role,
		PrimaryLanguageID:  req.PrimaryLanguageID,
		SecondaryLanguageID: req.SecondaryLanguageID,
		Email:              req.Email,
		AuthType:           req.AuthType,
		Password:           req.Password,
		ConfirmPassword:    req.ConfirmPassword,
		MuteNotifications:  req.MuteNotifications,
		Socials: &user.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
	}

	resp, err := uc.userClient.RegisterUser(c.Request.Context(), registerUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Registration failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) LoginUserHandler(c *gin.Context) {
	var req model.LoginUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	loginUserRequest := &user.LoginUserRequest{
		Email:    req.Email,
		Password: req.Password,
	}

	resp, err := uc.userClient.LoginUser(c.Request.Context(), loginUserRequest)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{Message: "Login failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) TokenRefreshHandler(c *gin.Context) {
	var req model.TokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	tokenRefreshRequest := &user.TokenRefreshRequest{
		RefreshToken: req.RefreshToken,
	}

	resp, err := uc.userClient.TokenRefresh(c.Request.Context(), tokenRefreshRequest)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{Message: "Token refresh failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) LogoutUserHandler(c *gin.Context) {
	var req model.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	logoutRequest := &user.LogoutRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.LogoutUser(c.Request.Context(), logoutRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Logout failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) ResendOTPHandler(c *gin.Context) {
	var req model.ResendOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	resendOTPRequest := &user.ResendOTPRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.ResendOTP(c.Request.Context(), resendOTPRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "OTP resend failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) VerifyUserHandler(c *gin.Context) {
	var req model.VerifyUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	verifyUserRequest := &user.VerifyUserRequest{
		Token: req.Token,
		Email: req.Email,
	}

	resp, err := uc.userClient.VerifyUser(c.Request.Context(), verifyUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Verification failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) SetTwoFactorAuthHandler(c *gin.Context) {
	var req model.SetTwoFactorAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	setTwoFactorAuthRequest := &user.SetTwoFactorAuthRequest{
		UserID: req.UserID,
		Enable: req.Enable,
	}

	resp, err := uc.userClient.SetTwoFactorAuth(c.Request.Context(), setTwoFactorAuthRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "2FA setup failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) ForgotPasswordHandler(c *gin.Context) {
	var req model.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	forgotPasswordRequest := &user.ForgotPasswordRequest{
		Email: req.Email,
	}

	resp, err := uc.userClient.ForgotPassword(c.Request.Context(), forgotPasswordRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Password recovery failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) ChangePasswordHandler(c *gin.Context) {
	var req model.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	changePasswordRequest := &user.ChangePasswordRequest{
		UserID:     req.UserID,
		NewPassword: req.NewPassword,
	}

	resp, err := uc.userClient.ChangePassword(c.Request.Context(), changePasswordRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Password change failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// User Management

func (uc *UserController) UpdateProfileHandler(c *gin.Context) {
	var req model.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	updateProfileRequest := &user.UpdateProfileRequest{
		UserID:             req.UserID,
		FirstName:          req.FirstName,
		LastName:           req.LastName,
		Country:            req.Country,
		PrimaryLanguageID:  req.PrimaryLanguageID,
		SecondaryLanguageID: req.SecondaryLanguageID,
		MuteNotifications:  req.MuteNotifications,
		Socials: &user.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
	}

	resp, err := uc.userClient.UpdateProfile(c.Request.Context(), updateProfileRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Profile update failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) UpdateProfileImageHandler(c *gin.Context) {
	var req model.UpdateProfileImageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	updateProfileImageRequest := &user.UpdateProfileImageRequest{
		UserID:     req.UserID,
		AvatarData: req.AvatarData,
	}

	resp, err := uc.userClient.UpdateProfileImage(c.Request.Context(), updateProfileImageRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Image update failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) GetUserProfileHandler(c *gin.Context) {
	var req model.GetUserProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	getUserProfileRequest := &user.GetUserProfileRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.GetUserProfile(c.Request.Context(), getUserProfileRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Profile retrieval failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) CheckBanStatusHandler(c *gin.Context) {
	var req model.CheckBanStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	checkBanStatusRequest := &user.CheckBanStatusRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.CheckBanStatus(c.Request.Context(), checkBanStatusRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Ban status check failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Social Features

func (uc *UserController) FollowUserHandler(c *gin.Context) {
	var req model.FollowUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	followUserRequest := &user.FollowUserRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.FollowUser(c.Request.Context(), followUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Follow failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) UnfollowUserHandler(c *gin.Context) {
	var req model.UnfollowUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	unfollowUserRequest := &user.UnfollowUserRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.UnfollowUser(c.Request.Context(), unfollowUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Unfollow failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) GetFollowingHandler(c *gin.Context) {
	var req model.GetFollowingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	getFollowingRequest := &user.GetFollowingRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.GetFollowing(c.Request.Context(), getFollowingRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Get following failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) GetFollowersHandler(c *gin.Context) {
	var req model.GetFollowersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	getFollowersRequest := &user.GetFollowersRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.GetFollowers(c.Request.Context(), getFollowersRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Get followers failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Admin Operations

func (uc *UserController) CreateUserAdminHandler(c *gin.Context) {
	var req model.CreateUserAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	createUserAdminRequest := &user.CreateUserAdminRequest{
		FirstName:          req.FirstName,
		LastName:           req.LastName,
		Country:            req.Country,
		Role:               req.Role,
		PrimaryLanguageID:  req.PrimaryLanguageID,
		SecondaryLanguageID: req.SecondaryLanguageID,
		Email:              req.Email,
		AuthType:           req.AuthType,
		Password:           req.Password,
		ConfirmPassword:    req.ConfirmPassword,
		MuteNotifications:  req.MuteNotifications,
		Socials: &user.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
	}

	resp, err := uc.userClient.CreateUserAdmin(c.Request.Context(), createUserAdminRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "User creation failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) UpdateUserAdminHandler(c *gin.Context) {
	var req model.UpdateUserAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	updateUserAdminRequest := &user.UpdateUserAdminRequest{
		UserID:             req.UserID,
		FirstName:          req.FirstName,
		LastName:           req.LastName,
		Country:            req.Country,
		Role:               req.Role,
		Email:              req.Email,
		Password:           req.Password,
		PrimaryLanguageID:  req.PrimaryLanguageID,
		SecondaryLanguageID: req.SecondaryLanguageID,
		MuteNotifications:  req.MuteNotifications,
		Socials: &user.Socials{
			Github:   req.Socials.Github,
			Twitter:  req.Socials.Twitter,
			Linkedin: req.Socials.Linkedin,
		},
	}

	resp, err := uc.userClient.UpdateUserAdmin(c.Request.Context(), updateUserAdminRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "User update failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) BlockUserHandler(c *gin.Context) {
	var req model.BlockUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	blockUserRequest := &user.BlockUserRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.BlockUser(c.Request.Context(), blockUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Block failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) UnblockUserHandler(c *gin.Context) {
	var req model.UnblockUserAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	unblockUserRequest := &user.UnblockUserAdminRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.UnblockUser(c.Request.Context(), unblockUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Unblock failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) VerifyAdminUserHandler(c *gin.Context) {
	var req model.VerifyAdminUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	verifyAdminUserRequest := &user.VerifyAdminUserRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.VerifyAdminUser(c.Request.Context(), verifyAdminUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Verification failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) UnverifyUserHandler(c *gin.Context) {
	var req model.UnverifyUserAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	unverifyUserRequest := &user.UnverifyUserAdminRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.UnverifyUser(c.Request.Context(), unverifyUserRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Unverification failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) SoftDeleteUserAdminHandler(c *gin.Context) {
	var req model.SoftDeleteUserAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	softDeleteUserAdminRequest := &user.SoftDeleteUserAdminRequest{
		UserID: req.UserID,
	}

	resp, err := uc.userClient.SoftDeleteUserAdmin(c.Request.Context(), softDeleteUserAdminRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Soft delete failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (uc *UserController) GetAllUsersHandler(c *gin.Context) {
	var req model.GetAllUsersRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Message: "Invalid request: " + err.Error()})
		return
	}

	getAllUsersRequest := &user.GetAllUsersRequest{
		Page:         req.Page,
		Limit:        req.Limit,
		RoleFilter:   req.RoleFilter,
		StatusFilter: req.StatusFilter,
	}

	resp, err := uc.userClient.GetAllUsers(c.Request.Context(), getAllUsersRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Message: "Get users failed: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}