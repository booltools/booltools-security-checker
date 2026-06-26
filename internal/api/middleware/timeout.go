package middleware

import (
	"context"
	"net/http"
	"time"
)

func TimeoutMiddleware(duration time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			ctx, cancel := context.WithTimeout(request.Context(), duration)
			defer cancel()
			next.ServeHTTP(writer, request.WithContext(ctx))
		})
	}
}
