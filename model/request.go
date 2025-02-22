package model

// Authentication and Security Requests
type RegisterUserRequest struct {
	FirstName           string   `json:"firstName"`
	LastName            string   `json:"lastName"`
	Country             string   `json:"country"`
	Role                string   `json:"role"`
	PrimaryLanguageID   string   `json:"primaryLanguageID"`
	SecondaryLanguageID []string `json:"secondaryLanguageID"`
	Email               string   `json:"email"`
	AuthType            string   `json:"authType"`
	Password            string   `json:"password"`
	ConfirmPassword     string   `json:"confirmPassword"`
	MuteNotifications   bool     `json:"muteNotifications"`
	Socials             Socials  `json:"socials"`
}

type LoginUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TokenRefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type LogoutRequest struct {
	UserID string `json:"userID"`
}

type ResendOTPRequest struct {
	UserID string `json:"userID"`
}

type VerifyUserRequest struct {
	Token string `json:"token"`
	Email string `json:"email"`
}

type SetTwoFactorAuthRequest struct {
	UserID string `json:"userID"`
	Enable bool   `json:"enable"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ChangePasswordRequest struct {
	UserID      string `json:"userID"`
	NewPassword string `json:"newPassword"`
}

// User Management Requests
type UpdateProfileRequest struct {
	UserID              string   `json:"userID"`
	FirstName           string   `json:"firstName"`
	LastName            string   `json:"lastName"`
	Country             string   `json:"country"`
	PrimaryLanguageID   string   `json:"primaryLanguageID"`
	SecondaryLanguageID []string `json:"secondaryLanguageID"`
	MuteNotifications   bool     `json:"muteNotifications"`
	Socials             Socials  `json:"socials"`
}

type UpdateProfileImageRequest struct {
	UserID     string `json:"userID"`
	AvatarData string `json:"avatarData"`
}

type GetUserProfileRequest struct {
	UserID string `json:"userID"`
}

type CheckBanStatusRequest struct {
	UserID string `json:"userID"`
}

// Social Features Requests
type FollowUserRequest struct {
	UserID string `json:"userID"`
}

type UnfollowUserRequest struct {
	UserID string `json:"userID"`
}

type GetFollowingRequest struct {
	UserID string `json:"userID"`
}

type GetFollowersRequest struct {
	UserID string `json:"userID"`
}

// Admin Operations Requests
type CreateUserAdminRequest struct {
	FirstName           string   `json:"firstName"`
	LastName            string   `json:"lastName"`
	Country             string   `json:"country"`
	Role                string   `json:"role"`
	PrimaryLanguageID   string   `json:"primaryLanguageID"`
	SecondaryLanguageID []string `json:"secondaryLanguageID"`
	Email               string   `json:"email"`
	AuthType            string   `json:"authType"`
	Password            string   `json:"password"`
	ConfirmPassword     string   `json:"confirmPassword"`
	MuteNotifications   bool     `json:"muteNotifications"`
	Socials             Socials  `json:"socials"`
}

type UpdateUserAdminRequest struct {
	UserID              string   `json:"userID"`
	FirstName           string   `json:"firstName"`
	LastName            string   `json:"lastName"`
	Country             string   `json:"country"`
	Role                string   `json:"role"`
	Email               string   `json:"email"`
	Password            string   `json:"password"`
	PrimaryLanguageID   string   `json:"primaryLanguageID"`
	SecondaryLanguageID []string `json:"secondaryLanguageID"`
	MuteNotifications   bool     `json:"muteNotifications"`
	Socials             Socials  `json:"socials"`
}

type BlockUserRequest struct {
	UserID string `json:"userID"`
}

type UnblockUserAdminRequest struct {
	UserID string `json:"userID"`
}

type VerifyAdminUserRequest struct {
	UserID string `json:"userID"`
}

type UnverifyUserAdminRequest struct {
	UserID string `json:"userID"`
}

type SoftDeleteUserAdminRequest struct {
	UserID string `json:"userID"`
}

type GetAllUsersRequest struct {
	Page         int32  `form:"page" binding:"min=1"`
	Limit        int32  `form:"limit" binding:"min=1,max=100"`
	RoleFilter   string `form:"roleFilter"`
	StatusFilter string `form:"statusFilter"`
}

// Common Request Structs
type Socials struct {
	Github   string `json:"github"`
	Twitter  string `json:"twitter"`
	Linkedin string `json:"linkedin"`
}
