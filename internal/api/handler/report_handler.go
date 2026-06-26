package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	secmcp "github.com/booltools/security-checker/internal/mcp"
)

type ReportHandler struct {
	auditTools *secmcp.AuditTools
}

func NewReportHandler(auditTools *secmcp.AuditTools) *ReportHandler {
	return &ReportHandler{auditTools: auditTools}
}

func (handler *ReportHandler) GetReport(writer http.ResponseWriter, request *http.Request) {
	sessionID := chi.URLParam(request, "id")
	if sessionID == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "session id is required"})
		return
	}

	report, err := handler.auditTools.GetReport(request.Context(), secmcp.GetReportInput{
		SessionID: sessionID,
	})
	if err != nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(writer, http.StatusOK, report)
}
