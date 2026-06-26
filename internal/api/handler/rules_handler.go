package handler

import (
	"net/http"

	secmcp "github.com/booltools/security-checker/internal/mcp"
)

type RulesHandler struct {
	searchTools *secmcp.SearchTools
}

func NewRulesHandler(searchTools *secmcp.SearchTools) *RulesHandler {
	return &RulesHandler{searchTools: searchTools}
}

func (handler *RulesHandler) SearchRules(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query().Get("q")
	if query == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "query parameter 'q' is required"})
		return
	}

	output, err := handler.searchTools.SearchRules(request.Context(), secmcp.SearchRulesInput{
		Query:      query,
		MaxResults: 20,
	})
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(writer, http.StatusOK, output)
}

func (handler *RulesHandler) GetRuleDetail(writer http.ResponseWriter, request *http.Request) {
	ruleID := request.URL.Query().Get("id")
	if ruleID == "" {
		writeJSON(writer, http.StatusBadRequest, map[string]string{"error": "query parameter 'id' is required"})
		return
	}

	output, err := handler.searchTools.GetRuleDetail(request.Context(), secmcp.GetRuleDetailInput{
		RuleID: ruleID,
	})
	if err != nil {
		writeJSON(writer, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(writer, http.StatusOK, output)
}
