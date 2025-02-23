package middleware

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"xcode/model"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
)

// Claims structure
type Claims struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// Context keys
const (
	EntityID = "ID"
	RoleKey  = "ROLE"
)

// Role constants
const (
	RoleAdmin = "ADMIN"
	RoleUser  = "USER"
)

// JWTAuthMiddleware handles JWT authentication and role verification
func JWTAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, model.GenericResponse{
				Success: false,
				Status:  http.StatusUnauthorized,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusUnauthorized,
					Message: "Authorization header is required",
				},
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, model.GenericResponse{
				Success: false,
				Status:  http.StatusUnauthorized,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusUnauthorized,
					Message: "Invalid token format",
				},
			})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, model.GenericResponse{
				Success: false,
				Status:  http.StatusUnauthorized,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusUnauthorized,
					Message: "Invalid or expired token",
					Details: err.Error(),
				},
			})
			c.Abort()
			return
		}

		if time.Now().Unix() > claims.ExpiresAt.Unix() {
			c.JSON(http.StatusUnauthorized, model.GenericResponse{
				Success: false,
				Status:  http.StatusUnauthorized,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusUnauthorized,
					Message: "Token has expired",
				},
			})
			c.Abort()
			return
		}

		c.Set(EntityID, claims.ID)
		c.Set(RoleKey, claims.Role)
		log.Printf("JWT validated - Path: %s, EntityID: %v, Role: %v", c.Request.URL.Path, claims.ID, claims.Role)
		c.Next()
	}
}

// RoleAuthMiddleware verifies if the user has one of the allowed roles
func RoleAuthMiddleware(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get(RoleKey)
		if !exists {
			c.JSON(http.StatusUnauthorized, model.GenericResponse{
				Success: false,
				Status:  http.StatusUnauthorized,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusUnauthorized,
					Message: "Role information not found",
				},
			})
			c.Abort()
			return
		}

		userRole := role.(string)
		for _, allowedRole := range allowedRoles {
			if userRole == allowedRole {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, model.GenericResponse{
			Success: false,
			Status:  http.StatusForbidden,
			Payload: nil,
			Error: &model.ErrorInfo{
				Code:    http.StatusForbidden,
				Message: "Insufficient role permissions",
				Details: "Required roles: " + strings.Join(allowedRoles, ", "),
			},
		})
		c.Abort()
	}
}

// UserBanCheckMiddleware checks if a user is banned before allowing access
func UserBanCheckMiddleware(userClient AuthUserAdminService.AuthUserAdminServiceClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		userId, exists := GetEntityID(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, model.GenericResponse{
				Success: false,
				Status:  http.StatusUnauthorized,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusUnauthorized,
					Message: "User ID not found in token",
				},
			})
			c.Abort()
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		response, err := userClient.CheckBanStatus(ctx, &AuthUserAdminService.CheckBanStatusRequest{
			UserID: userId,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, model.GenericResponse{
				Success: false,
				Status:  http.StatusInternalServerError,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusInternalServerError,
					Message: "Failed to check ban status",
					Details: err.Error(),
				},
			})
			c.Abort()
			return
		}

		if response.IsBanned {
			c.JSON(http.StatusForbidden, model.GenericResponse{
				Success: false,
				Status:  http.StatusForbidden,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusForbidden,
					Message: "User is banned",
				},
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetEntityID retrieves the user ID from the context
func GetEntityID(c *gin.Context) (string, bool) {
	ID, exists := c.Get(EntityID)
	if !exists {
		return "", false
	}
	return ID.(string), true
}

// GetEntityRole retrieves the user role from the context
func GetEntityRole(c *gin.Context) (string, bool) {
	role, exists := c.Get(RoleKey)
	if !exists {
		return "", false
	}
	return role.(string), true
}
