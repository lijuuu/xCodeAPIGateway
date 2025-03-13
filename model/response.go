package model


// UserProfile represents a user's profile information
type UserProfile struct {
    UserID            string  `json:"userID"`
    UserName          string  `json:"userName"`
    FirstName         string  `json:"firstName"`
    LastName          string  `json:"lastName"`
    AvatarURL         string  `json:"avatarURL"`
    Email             string  `json:"email"`
    Role              string  `json:"role"`
    Country           string  `json:"country"`
    IsBanned          bool    `json:"isBanned"`
    IsVerified        bool    `json:"isVerified"`
    PrimaryLanguageID string  `json:"primaryLanguageID"`
    MuteNotifications bool    `json:"muteNotifications"`
    Socials           Socials `json:"socials"`
    CreatedAt         int64   `json:"createdAt"`
}


// BanHistory represents a single ban record
type BanHistory struct {
    ID        string `json:"id"`
    UserID    string `json:"userID"`
    BannedAt  int64  `json:"bannedAt"`
    BanType   string `json:"banType"`
    BanReason string `json:"banReason"`
    BanExpiry int64  `json:"banExpiry"`
}

// Response structs for each handler
type RegisterUserResponse struct {
    UserID       string      `json:"userID"`
    AccessToken  string      `json:"accessToken"`
    RefreshToken string      `json:"refreshToken"`
    ExpiresIn    int32       `json:"expiresIn"`
    UserProfile  UserProfile `json:"userProfile"`
    Message      string      `json:"message"`
}

type LoginUserResponse struct {
    AccessToken  string      `json:"accessToken"`
    RefreshToken string      `json:"refreshToken"`
    ExpiresIn    int32       `json:"expiresIn"`
    UserID       string      `json:"userID"`
    UserProfile  UserProfile `json:"userProfile"`
    Message      string      `json:"message"`
}

type LoginAdminResponse struct {
    AccessToken  string `json:"accessToken"`
    RefreshToken string `json:"refreshToken"`
    ExpiresIn    int32  `json:"expiresIn"`
    AdminID      string `json:"adminID"`
    Message      string `json:"message"`
}

type TokenRefreshResponse struct {
    AccessToken string `json:"accessToken"`
    ExpiresIn   int32  `json:"expiresIn"`
    UserID      string `json:"userID"`
    Message     string `json:"message"`
}

type LogoutResponse struct {
    Message string `json:"message"`
}

type ResendEmailVerificationResponse struct {
    Message string `json:"message"`
    ExpiryAt int64  `json:"expiryAt"`
}

type VerifyUserResponse struct {
    Message string `json:"message"`
}

type ToggleTwoFactorAuthResponse struct {
    Message string `json:"message"`
}

type ForgotPasswordResponse struct {
    Message string `json:"message"`
    Token   string `json:"token"`
}

type FinishForgotPasswordResponse struct {
    Message string `json:"message"`
}

type ChangePasswordResponse struct {
    Message string `json:"message"`
}

type UpdateProfileResponse struct {
    Message     string      `json:"message"`
    UserProfile UserProfile `json:"userProfile"`
}

type UpdateProfileImageResponse struct {
    Message   string `json:"message"`
    AvatarURL string `json:"avatarURL"`
}

type GetUserProfileResponse struct {
    UserProfile UserProfile `json:"userProfile"`
    Message     string      `json:"message,omitempty"`
}

type CheckBanStatusResponse struct {
    IsBanned      bool   `json:"isBanned"`
    Reason        string `json:"reason"`
    BanExpiration int64  `json:"banExpiration"`
    Message       string `json:"message"`
}

type FollowUserResponse struct {
    Message string `json:"message"`
}

type UnfollowUserResponse struct {
    Message string `json:"message"`
}

type GetFollowingResponse struct {
    Users         []UserProfile `json:"users"`
    TotalCount    int32         `json:"totalCount"`
    NextPageToken string        `json:"nextPageToken"`
    Message       string        `json:"message"`
}

type GetFollowersResponse struct {
    Users         []UserProfile `json:"users"`
    TotalCount    int32         `json:"totalCount"`
    NextPageToken string        `json:"nextPageToken"`
    Message       string        `json:"message"`
}

type CreateUserAdminResponse struct {
    UserID  string `json:"userID"`
    Message string `json:"message"`
}

type UpdateUserAdminResponse struct {
    Message string `json:"message"`
}

type BanUserResponse struct {
    Message string `json:"message"`
}

type UnbanUserResponse struct {
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
    Users         []UserProfile `json:"users"`
    TotalCount    int32         `json:"totalCount"`
    NextPageToken string        `json:"nextPageToken"`
    Message       string        `json:"message"`
}

type BanHistoryResponse struct {
    Bans    []BanHistory `json:"bans"`
    Message string       `json:"message"`
}

type SearchUsersResponse struct {
    Users         []UserProfile `json:"users"`
    TotalCount    int32         `json:"totalCount"`
    NextPageToken string        `json:"nextPageToken"`
    Message       string        `json:"message"`
}

// GenericResponse remains unchanged
type GenericResponse struct {
    Success bool        `json:"success"`
    Status  int         `json:"status"`
    Payload interface{} `json:"payload,omitempty"`
    Error   *ErrorInfo  `json:"error,omitempty"`
}

type ErrorInfo struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
    Details string `json:"details,omitempty"`
}

type SetUpTwoFactorAuthResponse struct {
    Image   string `json:"image"`
    Secret  string `json:"secret"`
    Message string `json:"message"`
}

type GetTwoFactorAuthStatusResponse struct {
    IsEnabled bool   `json:"isEnabled"`
    Message   string `json:"message"`
}
