package handler

import (
	"encoding/json"
	"net/http"

	secmcp "github.com/booltools/security-checker/internal/mcp"
)

type AuditHandler struct {
	auditTools     *secmcp.AuditTools
	sessionManager *secmcp.SessionManager
}

func NewAuditHandler(auditTools *secmcp.AuditTools, sessionManager *secmcp.SessionManager) *AuditHandler {
	return &AuditHandler{
		auditTools:     auditTools,
		sessionManager: sessionManager,
	}
}

type StartAuditRequest struct {
	FolderPath  string   `json:"folder_path"`
	Language    string   `json:"language"`
	Framework   string   `json:"framework,omitempty"`
	Platform    string   `json:"platform,omitempty"`
	Tools       []string `json:"tools,omitempty"`
	AppliesTo   string   `json:"applies_to,omitempty"`
	MinSeverity string   `json:"min_severity,omitempty"`
}

func (handler *AuditHandler) StartAudit(writer http.ResponseWriter, request *http.Request) {
	var body StartAuditRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if body.Language == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "language is required"})
		return
	}

	output, err := handler.auditTools.StartAudit(request.Context(), secmcp.StartAuditInput{
		Language:    body.Language,
		Framework:   body.Framework,
		Platform:    body.Platform,
		Tools:       body.Tools,
		AppliesTo:   body.AppliesTo,
		MinSeverity: body.MinSeverity,
	})
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(writer, http.StatusOK, output)
}
