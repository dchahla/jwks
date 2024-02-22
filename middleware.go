// Package hmacmiddleware provides middleware for verifying JWT tokens using HMACSHA256.
// It ensures that incoming requests are properly authenticated before proceeding to the next handler.
// Author: Daniel Chahla
// Twitter: @dchahla
// Version: v1.0.0
package hmacmiddleware

import (
	"net/http"

	"github.com/golang-jwt/jwt"
)

// MiddlewareFunc represents a middleware function that takes an http.Handler and returns an http.Handler.
type MiddlewareFunc func(http.Handler) http.Handler

// Verify is a middleware that verifies JWT tokens using HMACSHA256.
// It takes in an HMACSHA256 secret string (your-256-bit-secret).
func Verify(HMACSHA256Secret string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract the JWT token from the request headers
			tokenString := extractToken(r)
			if tokenString == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Parse and validate the token
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Validate the token signing method
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				// Provide the HMACSHA256 secret to validate the token
				return []byte(HMACSHA256Secret), nil
			})

			if err != nil || !token.Valid {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Token is valid, call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// extractToken extracts the token from the request headers.
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}
