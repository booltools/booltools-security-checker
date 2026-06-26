package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	secmcp "github.com/booltools/security-checker/internal/mcp"
)

type ExportHandler struct {
	auditTools *secmcp.AuditTools
}

func NewExportHandler(auditTools *secmcp.AuditTools) *ExportHandler {
	return &ExportHandler{auditTools: auditTools}
}

func (handler *ExportHandler) ExportJSON(writer http.ResponseWriter, request *http.Request) {
	sessionID := chi.URLParam(request, "id")
	report, err := handler.auditTools.GetReport(request.Context(), secmcp.GetReportInput{
		SessionID: sessionID,
	})
	if err != nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=security-audit-%s.json", sessionID[:8]))

	jsonData, _ := json.MarshalIndent(report, "", "  ")
	writer.Write(jsonData)
}

func (handler *ExportHandler) ExportCSV(writer http.ResponseWriter, request *http.Request) {
	sessionID := chi.URLParam(request, "id")
	report, err := handler.auditTools.GetReport(request.Context(), secmcp.GetReportInput{
		SessionID: sessionID,
	})
	if err != nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writer.Header().Set("Content-Type", "text/csv")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=security-audit-%s.csv", sessionID[:8]))

	var builder strings.Builder
	builder.WriteString("Rule ID,Title,Severity,Status,Evidence\n")

	for _, failed := range report.FailedRules {
		builder.WriteString(fmt.Sprintf("%s,%s,%s,fail,%s\n",
			escapeCSV(failed.RuleID),
			escapeCSV(failed.Title),
			escapeCSV(failed.Severity),
			escapeCSV(failed.Evidence),
		))
	}

	writer.Write([]byte(builder.String()))
}

func (handler *ExportHandler) ExportMarkdown(writer http.ResponseWriter, request *http.Request) {
	sessionID := chi.URLParam(request, "id")
	report, err := handler.auditTools.GetReport(request.Context(), secmcp.GetReportInput{
		SessionID: sessionID,
	})
	if err != nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writer.Header().Set("Content-Type", "text/markdown")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=security-audit-%s.md", sessionID[:8]))

	var builder strings.Builder
	builder.WriteString("# Security Audit Report\n\n")
	builder.WriteString(fmt.Sprintf("**Score:** %s\n\n", report.Score))
	builder.WriteString(fmt.Sprintf("**Checked:** %d / %d rules\n\n", report.Checked, report.TotalRules))
	builder.WriteString(fmt.Sprintf("**Passed:** %d | **Failed:** %d | **Skipped:** %d\n\n", report.Passed, report.Failed, report.Skipped))

	if len(report.FailedRules) > 0 {
		builder.WriteString("## Failed Rules\n\n")
		builder.WriteString("| Severity | Rule | Evidence |\n")
		builder.WriteString("|----------|------|----------|\n")

		for _, failed := range report.FailedRules {
			builder.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
				failed.Severity,
				failed.Title,
				failed.Evidence,
			))
		}
	}

	writer.Write([]byte(builder.String()))
}

func escapeCSV(value string) string {
	if strings.ContainsAny(value, ",\"\n") {
		return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
	}
	return value
}
