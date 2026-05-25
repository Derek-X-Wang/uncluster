package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/derek-x-wang/uncluster/internal/api"
	"github.com/derek-x-wang/uncluster/internal/store"
)

// handleListCertEvents handles GET /v1/audit/certs.
//
// Query params:
//   - caller=<id>
//   - agent=<id>
//   - user=<username>
//   - outcome=signed|denied
//   - since=<seconds> (unix timestamp) or duration like "3600"
//   - limit=<n> (default 100, max 1000)
func (s *Server) handleListCertEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	f := store.CertEventFilter{
		CallerTokenID: q.Get("caller"),
		AgentID:       q.Get("agent"),
		Username:      q.Get("user"),
		Outcome:       q.Get("outcome"),
	}

	if sinceStr := q.Get("since"); sinceStr != "" {
		// Try as unix timestamp first; then as duration seconds.
		if ts, err := strconv.ParseInt(sinceStr, 10, 64); err == nil {
			t := time.Unix(ts, 0)
			f.Since = &t
		}
	}
	if limitStr := q.Get("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			f.Limit = n
		}
	}

	events, err := s.cfg.Store.ListCertEvents(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := make([]api.CertEventSummary, 0, len(events))
	for _, e := range events {
		out = append(out, api.CertEventSummary{
			RequestID:     e.RequestID,
			TS:            e.TS.Unix(),
			CallerTokenID: e.CallerTokenID,
			TargetAgentID: e.TargetAgentID,
			Username:      e.Username,
			CertPrincipal: e.CertPrincipal,
			PubkeyFP:      e.PubkeyFP,
			TTLSeconds:    e.TTLSeconds,
			Serial:        e.Serial,
			KeyID:         e.KeyID,
			Outcome:       e.Outcome,
			DenialReason:  e.DenialReason,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
