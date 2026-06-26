package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type contextKey string

const RequestIDKey contextKey = "request_id"

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := request.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}

		writer.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(request.Context(), RequestIDKey, requestID)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func generateRequestID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
