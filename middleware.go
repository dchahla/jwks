// hmacmiddleware is a minimalistic package for verifying id tokens using HMACSHA256.
// Daniel Chahla
// @dchahla
// version v1.0.0
package hmacmiddleware

import (
	"net/http"

	"github.com/golang-jwt/jwt"
)

// MiddlewareFunc is a type that represents a middleware function.
type MiddlewareFunc func(http.Handler) http.Handler
// verify is a middleware that verifies JWT tokens.
// Takes in HMACSHA256Secret string (your-256-bit-secret)
func verify(HMACSHA256Secret string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Validate the JWT token
            tokenString := extractToken(r)
            if tokenString == "" {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }
            token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
                // Validate the token signing method
                if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                    return nil, jwt.ErrSignatureInvalid
                }
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