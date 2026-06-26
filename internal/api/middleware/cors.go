package middleware

import (
	"net/http"
	"os"
	"strings"
)

func CORSMiddleware() func(http.Handler) http.Handler {
	allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	if allowedOrigins == "" {
		allowedOrigins = "*"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			origin := request.Header.Get("Origin")

			if allowedOrigins == "*" {
				writer.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				for _, allowed := range strings.Split(allowedOrigins, ",") {
					if strings.TrimSpace(allowed) == origin {
						writer.Header().Set("Access-Control-Allow-Origin", origin)
						break
					}
				}
			}

			writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			writer.Header().Set("Access-Control-Max-Age", "86400")

			if request.Method == http.MethodOptions {
				writer.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(writer, request)
		})
	}
}
