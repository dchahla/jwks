// tea is a package containing middleware functions.
package tea

import (
	"fmt"
	"net/http"
)

// MiddlewareFunc is a type that represents a middleware function.
type MiddlewareFunc func(http.Handler) http.Handler

// HandlerFunc is a type that represents a request handler function.
type HandlerFunc func(http.ResponseWriter, *http.Request)

// Time is a middleware that logs requests.
func Time(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Middleware logic goes here
        // For example, log the request
        fmt.Println("Request URL:", r.URL.String())
        
        // Call the next handler
        next.ServeHTTP(w, r)
    })
}

// MyHandler is an example request handler.
func MyHandler(w http.ResponseWriter, r *http.Request) {
    // Handler logic goes here
    // For example, write response
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Hello from MyHandler!"))
}
