package mcp

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/booltools/security-checker/internal/normalizer"
)

type AuditSession struct {
	ID           string
	Filter       normalizer.QueryFilter
	TotalRules   int
	CurrentIndex int
	Results      map[string]RuleResult
	CreatedAt    time.Time
}

type SessionManager struct {
	sessions map[string]*AuditSession
	mu       sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*AuditSession),
	}
}

func (sm *SessionManager) CreateSession(filter normalizer.QueryFilter, totalRules int) *AuditSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session := &AuditSession{
		ID:           uuid.New().String(),
		Filter:       filter,
		TotalRules:   totalRules,
		CurrentIndex: 0,
		Results:      make(map[string]RuleResult),
		CreatedAt:    time.Now(),
	}

	sm.sessions[session.ID] = session
	return session
}

func (sm *SessionManager) GetSession(sessionID string) (*AuditSession, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	return session, nil
}

func (sm *SessionManager) AdvanceIndex(sessionID string, count int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		session.CurrentIndex += count
	}
}

func (sm *SessionManager) RecordResults(sessionID string, results []RuleResult) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	for _, result := range results {
		session.Results[result.RuleID] = result
	}

	return nil
}

func (sm *SessionManager) GetProgress(sessionID string) (checked int, total int) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return 0, 0
	}
	return len(session.Results), session.TotalRules
}

func (sm *SessionManager) CleanupStale(maxAge time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for id, session := range sm.sessions {
		if session.CreatedAt.Before(cutoff) {
			delete(sm.sessions, id)
		}
	}
}
