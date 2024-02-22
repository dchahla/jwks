package tea

import (
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
)

// MiddlewareFunc is a type that represents a middleware function.
type MiddlewareFunc func(http.Handler) http.Handler

// JWTMiddleware is a middleware that verifies JWT tokens.
func JWTMiddleware(audience string) MiddlewareFunc {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Validate the JWT token
            tokenString := extractToken(r)
            if tokenString == "" {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // Parse the token
            token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
                // Check token signing method
                if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                    return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
                }
                // Provide the key to validate the token
                return []byte("your-secret-key"), nil
            })
            if err != nil {
                http.Error(w, err.Error(), http.StatusUnauthorized)
                return
            }

            // Validate token claims
            if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
                // Check audience claim
                if claims["aud"].(string) != audience {
                    http.Error(w, "Invalid audience", http.StatusUnauthorized)
                    return
                }
            } else {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
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
