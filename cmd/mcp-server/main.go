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

	secmcp "github.com/booltools/security-checker/internal/mcp"
)

func main() {
	dbPath := flag.String("db", "./security_rules.db", "Path to the security rules SQLite database")
	port := flag.String("port", "8788", "HTTP port for the MCP server")
	verbose := flag.Bool("verbose", false, "Enable debug logging")

	flag.Parse()

	logLevel := slog.LevelWarn
	if *verbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChannel
		cancel()
	}()

	server, err := secmcp.NewSecurityCheckerServer(*dbPath, logger)
	if err != nil {
		logger.Error("failed to create MCP server", "error", err)
		os.Exit(1)
	}
	defer server.Close()

	httpHandler := server.HTTPHandler()

	mux := http.NewServeMux()
	mux.Handle("/mcp", httpHandler)

	httpServer := &http.Server{
		Addr:              ":" + *port,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("Security Checker MCP server starting on http://localhost:%s/mcp", *port)
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
