package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/booltools/security-checker/internal/api/handler"
	"github.com/booltools/security-checker/internal/api/middleware"
	secmcp "github.com/booltools/security-checker/internal/mcp"
)

func NewRouter(
	auditTools *secmcp.AuditTools,
	searchTools *secmcp.SearchTools,
	sessionManager *secmcp.SessionManager,
) http.Handler {
	router := chi.NewRouter()

	router.Use(chimiddleware.Logger)
	router.Use(chimiddleware.Recoverer)
	router.Use(chimiddleware.RealIP)
	router.Use(middleware.RequestIDMiddleware)
	router.Use(middleware.SecurityHeadersMiddleware)
	router.Use(middleware.CORSMiddleware())
	router.Use(middleware.BodyLimitMiddleware)
	router.Use(middleware.CompressMiddleware)

	auditHandler := handler.NewAuditHandler(auditTools, sessionManager)
	reportHandler := handler.NewReportHandler(auditTools)
	sseHandler := handler.NewSSEHandler(auditTools)
	exportHandler := handler.NewExportHandler(auditTools)
	rulesHandler := handler.NewRulesHandler(searchTools)

	router.Route("/api", func(apiRouter chi.Router) {
		apiRouter.Use(middleware.RateLimitMiddleware(60))
		apiRouter.Use(middleware.TimeoutMiddleware(120 * time.Second))

		apiRouter.Post("/audit", auditHandler.StartAudit)
		apiRouter.Get("/audit/{id}/progress", sseHandler.StreamProgress)
		apiRouter.Get("/report/{id}", reportHandler.GetReport)
		apiRouter.Get("/report/{id}/export/json", exportHandler.ExportJSON)
		apiRouter.Get("/report/{id}/export/csv", exportHandler.ExportCSV)
		apiRouter.Get("/report/{id}/export/md", exportHandler.ExportMarkdown)
		apiRouter.Get("/rules", rulesHandler.SearchRules)
		apiRouter.Get("/rules/detail", rulesHandler.GetRuleDetail)

		apiRouter.Get("/health", func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.Write([]byte(`{"status":"ok"}`))
		})
	})

	return router
}
