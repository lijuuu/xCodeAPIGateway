package model

// ErrorResponse for generic error responses
type ErrorResponse struct {
	Message string `json:"message"`
}

// Authentication and Security Responses
type RegisterUserResponse struct {
	UserID  string `json:"userID"`
	Message string `json:"message"`
}

type LoginUserResponse struct {
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int32  `json:"expiresIn"`
	UserID       string `json:"userID"`
}

type TokenRefreshResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int32  `json:"expiresIn"`
	UserID      string `json:"userID"`
}

type LogoutResponse struct {
	Message string `json:"message"`
}

type ResendOTPResponse struct {
	Message string `json:"message"`
}

type VerifyUserResponse struct {
	Message string `json:"message"`
}

type SetTwoFactorAuthResponse struct {
	Message string `json:"message"`
}

type ForgotPasswordResponse struct {
	Message string `json:"message"`
}

type ChangePasswordResponse struct {
	Message string `json:"message"`
}

// User Management Responses
type UpdateProfileResponse struct {
	Message string `json:"message"`
}

type UpdateProfileImageResponse struct {
	Message    string `json:"message"`
	AvatarData string `json:"avatarData"`
}

type GetUserProfileResponse struct {
	FirstName string  `json:"firstName"`
	LastName  string  `json:"lastName"`
	Country   string  `json:"country"`
	Email     string  `json:"email"`
	Role      string  `json:"role"`
	Socials   Socials `json:"socials"`
}

type CheckBanStatusResponse struct {
	IsBanned      bool   `json:"isBanned"`
	Reason        string `json:"reason"`
	BanExpiration int64  `json:"banExpiration"`
	Message       string `json:"message"`
}

// Social Features Responses
type FollowUserResponse struct {
	Message string `json:"message"`
}

type UnfollowUserResponse struct {
	Message string `json:"message"`
}

type GetFollowingResponse struct {
	Data []UserProfile `json:"data"`
}

type GetFollowersResponse struct {
	Data []UserProfile `json:"data"`
}

// Admin Operations Responses
type CreateUserAdminResponse struct {
	UserID  string `json:"userID"`
	Message string `json:"message"`
}

type UpdateUserAdminResponse struct {
	Message string `json:"message"`
}

type BlockUserResponse struct {
	Message string `json:"message"`
}

type UnblockUserAdminResponse struct {
	Message string `json:"message"`
}

type VerifyAdminUserResponse struct {
	Message string `json:"message"`
}

type UnverifyUserAdminResponse struct {
	Message string `json:"message"`
}

type SoftDeleteUserAdminResponse struct {
	Message string `json:"message"`
}

type GetAllUsersResponse struct {
	Users      []UserProfile `json:"users"`
	TotalCount int32         `json:"totalCount"`
	Message    string        `json:"message"`
}

type UserProfile struct {
	UserID    string  `json:"userID"`
	FirstName string  `json:"firstName"`
	LastName  string  `json:"lastName"`
	Email     string  `json:"email"`
	Role      string  `json:"role"`
	Status    string  `json:"status"`
	Socials   Socials `json:"socials"`
}
