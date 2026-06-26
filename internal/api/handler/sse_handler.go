package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	secmcp "github.com/booltools/security-checker/internal/mcp"
)

type SSEHandler struct {
	auditTools *secmcp.AuditTools
}

func NewSSEHandler(auditTools *secmcp.AuditTools) *SSEHandler {
	return &SSEHandler{auditTools: auditTools}
}

type progressEvent struct {
	Type     string      `json:"type"`
	Data     interface{} `json:"data"`
	Progress string      `json:"progress"`
}

func (handler *SSEHandler) StreamProgress(writer http.ResponseWriter, request *http.Request) {
	sessionID := chi.URLParam(request, "id")
	if sessionID == "" {
		http.Error(writer, "session id is required", http.StatusBadRequest)
		return
	}

	flusher, ok := writer.(http.Flusher)
	if !ok {
		http.Error(writer, "streaming not supported", http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.Header().Set("X-Accel-Buffering", "no")

	ctx := request.Context()
	batchSize := 5
	batchNumber := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rulesOutput, err := handler.auditTools.GetRules(ctx, secmcp.GetRulesInput{
			SessionID: sessionID,
			BatchSize: batchSize,
		})
		if err != nil {
			sendSSEEvent(writer, "error", map[string]string{"error": err.Error()})
			flusher.Flush()
			return
		}

		if len(rulesOutput.Rules) == 0 {
			sendSSEEvent(writer, "complete", map[string]string{"message": "all rules served"})
			flusher.Flush()
			return
		}

		batchNumber++
		event := progressEvent{
			Type:     "rules_batch",
			Data:     rulesOutput.Rules,
			Progress: rulesOutput.Progress,
		}
		sendSSEEvent(writer, "progress", event)
		flusher.Flush()

		if rulesOutput.Remaining == 0 {
			sendSSEEvent(writer, "complete", map[string]string{"message": "all rules served"})
			flusher.Flush()
			return
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func sendSSEEvent(writer http.ResponseWriter, eventType string, data interface{}) {
	jsonData, _ := json.Marshal(data)
	fmt.Fprintf(writer, "event: %s\ndata: %s\n\n", eventType, string(jsonData))
}
