package main

import (
	"context"
	"flag"
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
	mcpMode := flag.Bool("mcp", false, "Start the MCP server instead of the API server")
	verbose := flag.Bool("verbose", false, "Enable debug logging")
	flag.Parse()

	if *mcpMode {
		runMCPServer(*verbose)
		return
	}

	runAPIServer()
}

func runMCPServer(verbose bool) {
	logLevel := slog.LevelWarn
	if verbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./security_rules.db"
	}

	port := os.Getenv("MCP_PORT")
	if port == "" {
		port = "8788"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChannel
		cancel()
	}()

	server, err := secmcp.NewSecurityCheckerServer(dbPath, port, logger)
	if err != nil {
		logger.Error("failed to create MCP server", "error", err)
		os.Exit(1)
	}
	defer server.Close()

	httpHandler := server.HTTPHandler()

	mux := http.NewServeMux()
	mux.Handle("/mcp", httpHandler)
	mux.HandleFunc("/audit/", server.RouteAuditHTTP)

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("Security Checker MCP server starting on http://localhost:%s/mcp", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("MCP HTTP server failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down MCP server...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	httpServer.Shutdown(shutdownCtx)
}

func runAPIServer() {
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
	auditTools := secmcp.NewAuditTools(database, sessionManager, "8788")
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
