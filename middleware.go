package googlemiddleware

import (
	"fmt"
	"net/http"
)

// MiddlewareFunc is a type that represents a middleware function.
type MiddlewareFunc func(http.Handler) http.Handler

// googleMiddleware is a middleware that logs requests.
func googleMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Middleware logic goes here
        // For example, log the request
        fmt.Println("Request URL:", r.URL.String())
        
        // Call the next handler
        next.ServeHTTP(w, r)
    })
}
