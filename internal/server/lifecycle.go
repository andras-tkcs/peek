package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const retentionCleanupInterval = 1 * time.Hour

// Close releases server resources (database connections, etc.).
func (s *Server) Close() error {
	s.CloseEventStreams()
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	if s.backends != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := s.backends.Close(ctx); err != nil {
			slog.Error("backends close", "err", err)
		}
		cancel()
	}
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}

func (s *Server) audit(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	slog.Info("audit", "action", "system", "detail", msg)
	s.persistAuditLog(s.ctx, "", "system", msg, "")
}

// auditRequest logs an audit event with the actor's IP from the request.
func (s *Server) auditRequest(r *http.Request, actor, action, detail string) {
	ip := s.clientIP(r)
	slog.Info("audit", "actor", actor, "action", action, "detail", detail, "ip", ip)
	s.persistAuditLog(r.Context(), actor, action, detail, ip)
}

func (s *Server) persistAuditLog(ctx context.Context, actor, action, detail, ip string) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.store.AddAuditLog(ctx, actor, action, detail, ip); err != nil {
		slog.Error("audit log write failed", "actor", actor, "action", action, "detail", detail, "ip", ip, "err", err)
	}
}

func (s *Server) startRetentionCleanup(ctx context.Context) {
	s.runRetentionCleanup(ctx, retentionCleanupInterval)
}

func (s *Server) runRetentionCleanup(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = retentionCleanupInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.runRetentionCleanupLoop(ctx, ticker.C, nil)
}

func (s *Server) runRetentionCleanupLoop(ctx context.Context, ticks <-chan time.Time, afterCleanup func()) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			s.cleanupExpired(ctx)
			if afterCleanup != nil {
				afterCleanup()
			}
		}
	}
}

func (s *Server) cleanupExpired(ctx context.Context) {
	retentionDays := s.settingInt(ctx, "retention_days", 0)
	if retentionDays <= 0 {
		return
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	uploads, err := s.store.ListUploadsOlderThan(ctx, cutoff)
	if err != nil {
		slog.Error("retention cleanup: list", "err", err)
		return
	}
	removed := 0
	for _, u := range uploads {
		if err := s.deleteUpload(ctx, u); err != nil {
			slog.Error("retention cleanup: delete upload", "slug", u.Slug, "err", err)
			continue
		}
		removed++
	}
	if removed > 0 {
		slog.Info("retention cleanup: removed expired uploads", "count", removed, "cutoff", cutoff.Format(time.DateOnly))
	}
	s.pruneOldVersions(ctx, cutoff)
}

func (s *Server) pruneOldVersions(ctx context.Context, cutoff time.Time) {
	versions, err := s.store.ListPrunableVersions(ctx, cutoff)
	if err != nil {
		slog.Error("retention cleanup: list versions", "err", err)
		return
	}
	pruned := 0
	for _, v := range versions {
		if err := s.storage.Delete(ctx, v.ObjectKey); err != nil {
			slog.Error("retention cleanup: delete version", "upload_id", v.UploadID, "version", v.Version, "err", err)
			continue
		}
		if err := s.store.DeleteUploadVersion(ctx, v.UploadID, v.Version); err != nil {
			slog.Error("retention cleanup: delete version", "upload_id", v.UploadID, "version", v.Version, "err", err)
			continue
		}
		if s.backends != nil {
			if err := s.backends.StopVersion(ctx, v.UploadID, v.Version); err != nil {
				slog.Warn("retention cleanup: stop backend", "upload_id", v.UploadID, "version", v.Version, "err", err)
			}
		}
		pruned++
	}
	if pruned > 0 {
		slog.Info("retention cleanup: pruned old versions", "count", pruned, "cutoff", cutoff.Format(time.DateOnly))
	}
}

// auditDetail formats key/value pairs as space-separated key=value fields. A
// value that is empty or contains a space, '=', '"', '\\' or a non-printable
// rune is written with strconv.Quote, so user-supplied text (page names, token
// names, account names) cannot forge or hide another field. Keys must be fixed
// identifiers. An odd trailing key gets an empty value.
func auditDetail(kv ...string) string {
	var b strings.Builder
	for i := 0; i < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(kv[i])
		b.WriteByte('=')
		v := ""
		if i+1 < len(kv) {
			v = kv[i+1]
		}
		b.WriteString(auditValue(v))
	}
	return b.String()
}

func auditValue(v string) string {
	if v == "" || strings.ContainsAny(v, " =\"\\") || strings.IndexFunc(v, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return strconv.Quote(v)
	}
	return v
}
