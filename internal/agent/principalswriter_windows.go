//go:build windows

package agent

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// PrincipalsWriter is the LocalSystem-side service that watches the spool for a
// desired-state submitted by the low-priv UnclusterAgent, re-validates it
// strictly (treating the agent as untrusted across the privilege boundary),
// renders the per-user AuthorizedPrincipalsFiles as SYSTEM-owned files with a
// PROTECTED {SYSTEM, Administrators} DACL, and reports an applied-status back to
// the spool (#127, ADR-0004 Windows amendment).
//
// Hard security properties (the load-bearing reason this is a separate service):
//   - It is network-less. It never opens a socket; it only touches two fixed
//     directories.
//   - Its target dir (WindowsPrincipalsDir) and the owner/DACL it stamps are
//     HARDCODED — none come from the spool. A compromised agent can at most
//     submit a desired-state; it can never make the writer write outside
//     auth_principals or with a weaker owner/DACL.
//   - It re-runs validateUsername/validateCallerTokenID on every entry, so a
//     traversal username or a glob/newline-bearing caller_token_id that somehow
//     reached the spool is rejected and never written.
//   - It runs with SERVICE_REQUIRED_PRIVILEGES stripped to the minimum by SCM
//     (set at install time), so even though it is LocalSystem it holds far less
//     than a default LocalSystem process.
type PrincipalsWriter struct {
	logger      *slog.Logger
	principals  string // target dir; hardcoded via NewPrincipalsWriter
	policyPath  string // spool desired-state path
	appliedPath string // spool applied-status path
	poll        time.Duration

	lastDigest string // digest of the last desired-state we acted on (dedupe)
}

// NewPrincipalsWriter constructs the writer bound to the FIXED Windows paths.
// The principals dir is the compiled-in constant, never spool-derived.
func NewPrincipalsWriter(logger *slog.Logger) *PrincipalsWriter {
	if logger == nil {
		logger = slog.Default()
	}
	return &PrincipalsWriter{
		logger:      logger,
		principals:  WindowsPrincipalsDir,
		policyPath:  spoolPolicyPath(),
		appliedPath: spoolAppliedPath(),
		poll:        1 * time.Second,
	}
}

// Run blocks until ctx is cancelled, polling the spool for new desired-states
// and applying each. It is the writer service's main loop (driven by the SCM
// handler in cmd/uncluster/principals_writer_windows.go). Polling (rather than a
// directory-change notification) is deliberate: it is simple, durable across a
// writer restart (it re-reads whatever desired-state is on the spool at
// startup), and cheap at a 1s cadence — policy changes are rare and ≤10s
// latency end-to-end is already the system's heartbeat budget.
func (w *PrincipalsWriter) Run(ctx context.Context) error {
	w.logger.Info("principals-writer: starting", "principals_dir", w.principals, "spool", SpoolDir())
	t := time.NewTicker(w.poll)
	defer t.Stop()
	// Apply once immediately so a desired-state present at startup is handled
	// without waiting a full poll interval.
	w.tick()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("principals-writer: stopping")
			return nil
		case <-t.C:
			w.tick()
		}
	}
}

// tick reads the spool desired-state and, if it is new (different digest from
// the last one we acted on), applies it via the shared platform-neutral core
// and writes the applied-status. A missing spool file is normal before the
// first policy apply and is ignored.
//
// The actual re-validation + render (and the owner/DACL hardening inside
// restrictPrincipalsFileACL) lives in applyDesiredStateBytes; tick only handles
// the spool read, dedupe, status write, and logging so the security-critical
// path is the SAME code the cross-platform tests exercise.
func (w *PrincipalsWriter) tick() {
	b, err := os.ReadFile(w.policyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			w.logger.Warn("principals-writer: read spool", "err", err)
		}
		return
	}
	digest := desiredStateDigest(b)
	if digest == w.lastDigest {
		return // unchanged since we last acted; nothing to do
	}

	st := applyDesiredStateBytes(w.principals, b)
	if st.Status == "ok" {
		w.logger.Info("principals-writer: applied", "version", st.AppliedVersion, "hash", st.AppliedHash)
	} else {
		w.logger.Warn("principals-writer: apply failed", "version", st.AppliedVersion, "err", st.Error)
	}
	w.writeApplied(st)
	// Only advance lastDigest on a successful apply, so a transient failure
	// (e.g. principals dir briefly unwritable) is retried on the next tick
	// rather than latched off until the desired-state changes again.
	if st.Status == "ok" {
		w.lastDigest = digest
	}
}

// writeApplied atomically writes the applied-status to the spool so the agent
// can resolve its apply. A write failure is logged but cannot be reported (the
// reporting channel itself failed); the agent will then time out → failed
// apply, which is the safe outcome.
func (w *PrincipalsWriter) writeApplied(st appliedStatus) {
	b, err := marshalAppliedStatus(st)
	if err != nil {
		w.logger.Error("principals-writer: marshal applied-status", "err", err)
		return
	}
	if err := atomicWriteSpoolFile(w.appliedPath, b); err != nil {
		w.logger.Error("principals-writer: write applied-status", "err", err)
	}
}
