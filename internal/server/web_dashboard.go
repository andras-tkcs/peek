package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/andras-tkcs/peek/internal/models"
	"github.com/andras-tkcs/peek/internal/uploads"
	webui "github.com/andras-tkcs/peek/internal/web"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	if s.setupRequired(r.Context()) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderDashboard(w, r, owner, http.StatusOK, r.URL.Query(), "")
}

// renderDashboard renders owner's dashboard. Flash codes come from q; when
// inlineError is set it is shown as the error toast instead (used by handlers
// that answer a POST with the page rather than a redirect).
func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, owner *models.Account, status int, q url.Values, inlineError string) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	var list []models.Upload
	var listErr error
	if owner.IsAdmin {
		list, listErr = s.store.ListAllUploads(r.Context())
	} else {
		list, listErr = s.store.ListUploadsByOwner(r.Context(), owner.ID)
	}
	if listErr != nil {
		slog.Error("dashboard upload list failed", "account_id", owner.ID, "admin", owner.IsAdmin, "err", listErr)
	}
	uploads := make([]dashUpload, 0, len(list))
	for _, u := range list {
		uploads = append(uploads, dashUpload{
			Slug: u.Slug, Name: u.Name,
			SizeHuman: humanSize(u.Size), Visibility: u.Visibility,
			CreatedHuman: u.CreatedAt.Format("2006-01-02 15:04"),
		})
	}
	ids := make([]int64, 0, len(list))
	for _, u := range list {
		ids = append(ids, u.ID)
	}
	grantsByUpload, err := s.store.ListUploadGrantsForUploads(r.Context(), ids)
	if err != nil {
		slog.Error("dashboard grant list failed", "account_id", owner.ID, "err", err)
	}
	for i, u := range list {
		for _, g := range grantsByUpload[u.ID] {
			uploads[i].Grants = append(uploads[i].Grants, dashGrant{Kind: g.Kind, Email: g.Email})
		}
	}
	csrf, ok := s.csrfToken(w)
	if !ok {
		return
	}
	dashData_ := dashData{
		CSRF:    csrf,
		User:    owner.Name,
		IsAdmin: owner.IsAdmin,
		Uploads: uploads,
		APIKeys: s.dashboardAPIKeyRows(r.Context(), owner.ID),

		GroupGrantsEnabled: s.groups != nil,
		ManageSlug:         q.Get("manage"),
	}
	if listErr != nil {
		dashData_.UploadError = "uploads could not be loaded"
	}
	flash := resolveFlash(q, uploads, s.baseURL)
	if flash.Error != "" {
		dashData_.UploadError = flash.Error
	}
	if inlineError != "" {
		dashData_.UploadError = inlineError
	}
	dashData_.FlashSuccess = flash.Success
	dashData_.UploadSuccessURL = flash.UploadedURL
	s.renderHTML(w, status, webui.TemplateDashboard, dashData_)
}

func (s *Server) handleDashboardUpload(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	maxUpload := s.settingInt64(r.Context(), "max_upload", 2<<20)

	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+1024)
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		dashboardError(w, r, flashFormInvalid)
		return
	}
	validCSRF, err := s.validateCSRF(r, w, r.FormValue("csrf"))
	if err != nil {
		s.renderCSRFError(w, err)
		return
	}
	if !validCSRF {
		dashboardError(w, r, flashInvalidSession)
		return
	}

	mode := r.FormValue("mode")
	visibility := strings.TrimSpace(r.FormValue("visibility"))
	name := strings.TrimSpace(r.FormValue("name"))

	var data []byte
	if mode == "paste" {
		html := strings.TrimSpace(r.FormValue("html"))
		if html == "" {
			dashboardError(w, r, flashNoHTML)
			return
		}
		data = []byte(html)
		if name == "" {
			name = "pasted"
		}
	} else {
		file, header, err := r.FormFile("file")
		if err != nil {
			dashboardError(w, r, flashNoFile)
			return
		}
		defer file.Close()
		data, err = io.ReadAll(io.LimitReader(file, maxUpload+1))
		if err != nil || int64(len(data)) > maxUpload {
			dashboardError(w, r, flashFileTooLarge)
			return
		}
		if name == "" {
			name = header.Filename
		}
	}

	up, err := s.uploadService().Create(r.Context(), uploads.CreateInput{
		OwnerAccountID: owner.ID,
		Name:           name,
		Visibility:     visibility,
		Data:           data,
		Limits:         s.uploadLimits(r.Context()),
	})
	if err != nil {
		logUploadError(err)
		dashboardError(w, r, uploadFlashCode(err))
		return
	}
	s.auditRequest(r, owner.Name, "upload.create", auditDetail("slug", up.Slug, "name", up.Name, "size", strconv.Itoa(up.Size)))
	dashboardUploaded(w, r, up.Slug)
}

func (s *Server) handleDashboardDelete(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	slug := r.PathValue("slug")
	if !s.parseDashboardForm(w, r) {
		return
	}
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		dashboardError(w, r, flashNotFound)
		return
	}
	if u.OwnerAccountID != owner.ID && !owner.IsAdmin {
		dashboardError(w, r, flashNotOwner)
		return
	}
	if err := s.deleteUpload(r.Context(), *u); err != nil {
		slog.Error("dashboard upload delete failed", "slug", slug, "err", err)
		dashboardError(w, r, flashDeleteFailed)
		return
	}
	s.auditRequest(r, owner.Name, "upload.delete", auditDetail("slug", slug, "name", u.Name))
	dashboardHome(w, r)
}

func (s *Server) handleDashboardVisibility(w http.ResponseWriter, r *http.Request) {
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	slug := r.PathValue("slug")
	if !s.parseDashboardForm(w, r) {
		return
	}
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		dashboardError(w, r, flashNotFound)
		return
	}
	if u.OwnerAccountID != owner.ID && !owner.IsAdmin {
		dashboardError(w, r, flashNotOwner)
		return
	}
	visibility, err := uploads.PrepareVisibility(r.FormValue("visibility"))
	if err != nil {
		dashboardError(w, r, uploadFlashCode(err))
		return
	}
	if err := s.store.SetUploadVisibility(r.Context(), u.ID, visibility); err != nil {
		slog.Error("dashboard visibility update failed", "slug", slug, "err", err)
		dashboardError(w, r, flashVisibilityFailed)
		return
	}
	s.auditRequest(r, owner.Name, "upload.visibility.set", auditDetail("slug", slug, "visibility", visibility))
	if visibility == models.UploadVisibilityRestricted {
		dashboardFlashManage(w, r, "ok", flashVisibilitySet, slug)
		return
	}
	dashboardOKSlug(w, r, flashVisibilitySet, slug)
}

func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	w.Header().Set("Content-Security-Policy", webui.DashboardCSP)
	owner, ok := s.webAuth(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	slug := r.PathValue("slug")
	u, err := s.store.GetUpload(r.Context(), slug)
	if err != nil {
		s.renderWebError(w, http.StatusNotFound, "Stats not found", "Stats for this page could not be found.")
		return
	}
	if u.OwnerAccountID != owner.ID && !owner.IsAdmin {
		s.renderWebError(w, http.StatusNotFound, "Stats not found", "Stats for this page could not be found.")
		return
	}
	total, unique, err := s.store.CountVisits(r.Context(), u.ID)
	if err != nil {
		slog.Error("dashboard stats count failed", "slug", slug, "err", err)
		s.renderDashboardStatsError(w, slug, u.Name)
		return
	}
	recent, err := s.store.RecentVisits(r.Context(), u.ID, 100)
	if err != nil {
		slog.Error("dashboard stats visits failed", "slug", slug, "err", err)
		s.renderDashboardStatsError(w, slug, u.Name)
		return
	}
	const daySeconds = 86400
	const statsBucketCount = 7
	since := bucketStart(time.Now().Add(-time.Duration(statsBucketCount-1)*24*time.Hour), daySeconds)
	buckets, err := s.store.VisitBuckets(r.Context(), u.ID, since, daySeconds)
	if err != nil {
		slog.Error("dashboard stats buckets failed", "slug", slug, "err", err)
		s.renderDashboardStatsError(w, slug, u.Name)
		return
	}
	sparkline := statsSparkline(fillBuckets(buckets, since, daySeconds, statsBucketCount))
	visits := make([]statsVisit, 0, len(recent))
	for _, v := range recent {
		name := v.VisitorName
		if name == "" {
			name = ""
		}
		visits = append(visits, statsVisit{
			Name: name, IP: v.IP, UA: v.UserAgent,
			WhenHuman: v.VisitedAt.Format("2006-01-02 15:04"),
		})
	}
	s.renderHTML(w, http.StatusOK, webui.TemplateStats, statsData{
		Slug: slug, Name: u.Name,
		TotalVisits: total, UniqueVisitors: unique, Sparkline: sparkline, Recent: visits,
	})
}

func (s *Server) renderDashboardStatsError(w http.ResponseWriter, slug, name string) {
	s.renderHTML(w, http.StatusInternalServerError, webui.TemplateStats, statsData{
		Slug: slug, Name: name, Error: "stats could not be loaded",
	})
}

func statsSparkline(buckets []bucket) statsSparklineData {
	const (
		w   = 168.0
		h   = 56.0
		pad = 2.0
	)
	counts := make([]int, len(buckets))
	maxCount := 0
	total := 0
	for i, b := range buckets {
		counts[i] = b.Count
		total += b.Count
		if b.Count > maxCount {
			maxCount = b.Count
		}
	}
	if maxCount == 0 {
		maxCount = 1
	}
	stepX := 0.0
	if len(counts) > 1 {
		stepX = (w - pad*2) / float64(len(counts)-1)
	}
	points := ""
	lastX := pad
	lastY := h - pad
	for i, count := range counts {
		x := pad + float64(i)*stepX
		y := h - pad - (float64(count)/float64(maxCount))*(h-pad*4)
		if i == 0 {
			points = fmt.Sprintf("M %.1f %.1f", x, y)
		} else {
			points += fmt.Sprintf(" L %.1f %.1f", x, y)
		}
		lastX = x
		lastY = y
	}
	if points == "" {
		points = fmt.Sprintf("M %.1f %.1f", pad, h-pad)
	}
	area := points + fmt.Sprintf(" L %.1f %.1f L %.1f %.1f Z", lastX, h-pad, pad, h-pad)
	return statsSparklineData{
		Summary:  fmt.Sprintf("%s last 7 days", visitCountLabel(total)),
		LinePath: points,
		AreaPath: area,
		LastX:    fmt.Sprintf("%.1f", lastX),
		LastY:    fmt.Sprintf("%.1f", lastY),
	}
}

func visitCountLabel(n int) string {
	if n == 1 {
		return "1 visit"
	}
	return fmt.Sprintf("%d visits", n)
}
