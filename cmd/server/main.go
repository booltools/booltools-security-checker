package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/booltools/security-checker/internal/api"
	secmcp "github.com/booltools/security-checker/internal/mcp"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "security_rules.db"
	}

	database, err := secmcp.NewRulesDatabase(dbPath, logger)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	sessionManager := secmcp.NewSessionManager()
	auditTools := secmcp.NewAuditTools(database, sessionManager)
	searchTools := secmcp.NewSearchTools(database)

	router := api.NewRouter(auditTools, searchTools, sessionManager)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8787"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		log.Printf("Security Checker API server starting on port %s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	log.Println("server stopped")
}
