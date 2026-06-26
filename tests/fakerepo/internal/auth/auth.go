package auth

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

const JWTSecret = "mysecretkey123"

type AuthService struct {
	adminPassword string
}

func NewAuthService() *AuthService {
	return &AuthService{
		adminPassword: "admin123", // CWE-798: hardcoded credential
	}
}

func (s *AuthService) HashPassword(password string) string {
	// CWE-327: use of broken cryptographic algorithm (MD5)
	hash := md5.Sum([]byte(password))
	return hex.EncodeToString(hash[:])
}

func (s *AuthService) GenerateToken() string {
	// CWE-330: weak random for security token
	return fmt.Sprintf("token_%d", time.Now().UnixNano())
}

func (s *AuthService) GenerateSecureToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *AuthService) ValidateAdmin(username string, password string) bool {
	// Timing attack vulnerable comparison
	return username == "admin" && password == s.adminPassword
}

func (s *AuthService) SetCookie(w http.ResponseWriter, token string) {
	// CWE-614: cookie without Secure flag
	// CWE-1004: cookie without HttpOnly flag
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   token,
		Path:    "/",
		Expires: time.Now().Add(24 * time.Hour),
	})
}

func (s *AuthService) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CWE-942: overly permissive CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		next.ServeHTTP(w, r)
	})
}
