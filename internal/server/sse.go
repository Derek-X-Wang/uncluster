package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// sseWriter wraps an http.ResponseWriter + http.Flusher to emit SSE frames.
type sseWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

// newSSE sets the required SSE headers and returns a sseWriter.
// Returns (nil, false) if w does not implement http.Flusher — the caller
// must respond with 500 and return.
func newSSE(w http.ResponseWriter) (*sseWriter, bool) {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // disable nginx buffering when behind a proxy
	w.WriteHeader(http.StatusOK)
	f.Flush()
	return &sseWriter{w: w, f: f}, true
}

// Send encodes v as JSON and writes a single SSE frame:
//
//	event: <kind>
//	data: <json>\n\n
//
// It flushes immediately so the client receives the frame without buffering.
func (s *sseWriter) Send(kind string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("sse marshal %s: %w", kind, err)
	}
	if _, err := fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", kind, data); err != nil {
		return fmt.Errorf("sse write %s: %w", kind, err)
	}
	s.f.Flush()
	return nil
}
