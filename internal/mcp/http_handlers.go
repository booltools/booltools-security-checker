package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func (s *SecurityCheckerServer) HandleDownloadRules(writer http.ResponseWriter, request *http.Request) {
	sessionID := extractSessionID(request.URL.Path, "/audit/", "/rules.json")
	if sessionID == "" {
		http.Error(writer, "missing session_id", http.StatusBadRequest)
		return
	}

	session, err := s.sessionManager.GetSession(sessionID)
	if err != nil {
		http.Error(writer, "session not found", http.StatusNotFound)
		return
	}

	rules, err := s.database.QueryRules(session.Filter)
	if err != nil {
		http.Error(writer, "failed to query rules", http.StatusInternalServerError)
		return
	}

	agentRules := make([]RuleForAgent, 0, len(rules))
	for _, rule := range rules {
		agentRules = append(agentRules, RuleForAgent{
			ID:               rule.ID,
			Source:           rule.Source,
			Category:         rule.Category,
			Severity:         rule.Severity,
			Title:            rule.Title,
			CheckInstruction: rule.CheckInstruction,
		})
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=audit_%s_rules.json", sessionID[:8]))
	json.NewEncoder(writer).Encode(agentRules)
}

func (s *SecurityCheckerServer) HandleUploadResults(writer http.ResponseWriter, request *http.Request) {
	sessionID := extractSessionID(request.URL.Path, "/audit/", "/results")
	if sessionID == "" {
		http.Error(writer, "missing session_id", http.StatusBadRequest)
		return
	}

	_, err := s.sessionManager.GetSession(sessionID)
	if err != nil {
		http.Error(writer, "session not found", http.StatusNotFound)
		return
	}

	var results []RuleResult
	if err := json.NewDecoder(request.Body).Decode(&results); err != nil {
		http.Error(writer, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := s.sessionManager.RecordResults(sessionID, results); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	checked, total := s.sessionManager.GetProgress(sessionID)

	response := ReportResultsOutput{
		Acknowledged: len(results),
		TotalChecked: checked,
		TotalRules:   total,
		Progress: fmt.Sprintf("%d/%d rules checked (%.0f%%)",
			checked, total, float64(checked)/float64(total)*100),
	}

	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(response)
}

func (s *SecurityCheckerServer) RouteAuditHTTP(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path

	switch {
	case strings.HasSuffix(path, "/rules.json") && request.Method == http.MethodGet:
		s.HandleDownloadRules(writer, request)
	case strings.HasSuffix(path, "/results") && request.Method == http.MethodPost:
		s.HandleUploadResults(writer, request)
	default:
		http.Error(writer, "not found", http.StatusNotFound)
	}
}

func extractSessionID(path string, prefix string, suffix string) string {
	after := strings.TrimPrefix(path, prefix)
	if after == path {
		return ""
	}
	before := strings.TrimSuffix(after, suffix)
	if before == after {
		return ""
	}
	return before
}
