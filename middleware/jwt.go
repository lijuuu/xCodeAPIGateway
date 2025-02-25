package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"xcode/model"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	AuthUserAdminService "github.com/lijuuu/GlobalProtoXcode/AuthUserAdminService"
	logrus "github.com/sirupsen/logrus"
)

// Claims structure
type Claims struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}

// Context keys
const (
	EntityIDKey = "entityID" // Lowercase for consistency
	RoleKey     = "role"     // Lowercase for consistency
)

// Role constants
const (
	RoleAdmin = "ADMIN"
	RoleUser  = "USER"
)

// JWTAuthMiddleware handles JWT authentication
func JWTAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	fmt.Println("JWTAuthMiddleware ", jwtSecret)
	logger := logrus.New() // Use logrus for consistency
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

		// Expiration already checked by jwt.ParseWithClaims, no need for extra check
		c.Set(EntityIDKey, claims.ID)
		c.Set(RoleKey, claims.Role)

		logger.Printf("JWT validated - Path: %s, EntityID: %v, Role: %v", c.Request.URL.Path, claims.ID, claims.Role)
		c.Next()
	}
}

// RoleAuthMiddleware verifies if the user has one of the allowed roles
func RoleAuthMiddleware(allowedRoles ...string) gin.HandlerFunc {
	logger := logrus.New()
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

		userRole, ok := role.(string)
		if !ok {
			logger.Errorf("Invalid role type in context: %v", role)
			c.JSON(http.StatusInternalServerError, model.GenericResponse{
				Success: false,
				Status:  http.StatusInternalServerError,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Details: "Invalid role type",
				},
			})
			c.Abort()
			return
		}

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

// UserBanCheckMiddleware checks if a user is banned
func UserBanCheckMiddleware(userClient AuthUserAdminService.AuthUserAdminServiceClient) gin.HandlerFunc {
	logger := logrus.New()
	const timeout = 10 * time.Second // Could be made configurable
	return func(c *gin.Context) {
		if userClient == nil {
			logger.Errorf("User client is nil")
			c.JSON(http.StatusInternalServerError, model.GenericResponse{
				Success: false,
				Status:  http.StatusInternalServerError,
				Payload: nil,
				Error: &model.ErrorInfo{
					Code:    http.StatusInternalServerError,
					Message: "Internal server error",
					Details: "User client not provided",
				},
			})
			c.Abort()
			return
		}

		userID, exists := GetEntityID(c)
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

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Pass the user ID in the RPC context
		rpcCtx := context.WithValue(ctx, "userID", userID)

		response, err := userClient.CheckBanStatus(rpcCtx, &AuthUserAdminService.CheckBanStatusRequest{
			UserID: userID,
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
	id, exists := c.Get(EntityIDKey)
	if !exists {
		return "", false
	}
	userID, ok := id.(string)
	if !ok {
		logrus.Errorf("Invalid entity ID type in context: %v", id)
		return "", false
	}
	return userID, true
}

// GetEntityRole retrieves the user role from the context
func GetEntityRole(c *gin.Context) (string, bool) {
	role, exists := c.Get(RoleKey)
	if !exists {
		return "", false
	}
	userRole, ok := role.(string)
	if !ok {
		logrus.Errorf("Invalid role type in context: %v", role)
		return "", false
	}
	return userRole, true
}
