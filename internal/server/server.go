// Package server menyediakan endpoint OpenAI-compatible yang
// meneruskan request ke proxy inference AutoClaw dengan round-robin multi-akun.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hirotomasato/autoclawpi/internal/client"
	"github.com/hirotomasato/autoclawpi/internal/db"
)

// Server adalah proxy server OpenAI-compatible.
type Server struct {
	cl      *client.Client
	rrIndex int
	mu      sync.Mutex
	apiKey  string
	limiter *RateLimiter
}

// New membuat server baru.
func New(cl *client.Client) *Server {
	return &Server{
		cl:      cl,
		rrIndex: 0,
		limiter: NewRateLimiter(1.0/1.5, 3), // default: 1 req/1.5s, burst 3
	}
}

// WithRateLimit mengatur rate limiter (token/detik + burst).
func (s *Server) WithRateLimit(ratePerSec float64, burst int) *Server {
	if ratePerSec > 0 && burst > 0 {
		s.limiter = NewRateLimiter(ratePerSec, burst)
	}
	return s
}

// WithAPIKey mengatur API key untuk proteksi endpoint.
func (s *Server) WithAPIKey(key string) *Server {
	if key != "" {
		s.apiKey = key
	}
	return s
}

// Handler mengembalikan http.Handler yang menangani route OpenAI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", s.wrapAuth(s.handleChat))
	mux.HandleFunc("/v1/models", s.wrapAuth(s.handleModels))
	mux.HandleFunc("/healthz", s.handleHealth)
	return mux
}

// wrapAuth melindungi endpoint dengan API key jika dikonfigurasi.
func (s *Server) wrapAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got != s.apiKey {
				writeOpenAIError(w, 401, "invalid_api_key", "API key lokal salah")
				return
			}
		}
		next(w, r)
	}
}

// handleChat menangani /v1/chat/completions.
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = r.Body.Close()
	if err != nil {
		writeOpenAIError(w, 400, "invalid_request_error", "gagal baca body: "+err.Error())
		return
	}

	var req struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeOpenAIError(w, 400, "invalid_request_error", "gagal parse body: "+err.Error())
		return
	}
	if req.Model == "" {
		writeOpenAIError(w, 400, "invalid_request_error", "model required")
		return
	}

	// Model di luar katalog: gagal cepat, jangan buang request ke semua akun.
	if !client.KnownModel(req.Model) {
		writeOpenAIError(w, 400, "invalid_model",
			fmt.Sprintf("model %q tidak dikenal; pilihan: %s", req.Model, strings.Join(client.SupportedModels(), ", ")))
		return
	}

	route := client.RouteID(req.Model)
	upstreamBody, err := replaceModel(raw, client.BodyModel(route))
	if err != nil {
		writeOpenAIError(w, 400, "invalid_request_error", "gagal olah body: "+err.Error())
		return
	}

	accounts, _ := db.ListAccounts()
	usable := filterUsableAccounts(accounts)
	if len(usable) == 0 {
		writeOpenAIError(w, 503, "no_accounts", "tidak ada akun aktif tersedia")
		return
	}

	// Rate limit: tunggu token sebelum menyentuh upstream (hindari WAF block)
	if s.limiter != nil {
		if err := s.limiter.Wait(r.Context()); err != nil {
			writeOpenAIError(w, 503, "rate_limited", "request dibatalkan: "+err.Error())
			return
		}
	}

	s.mu.Lock()
	startIdx := s.rrIndex % len(usable)
	s.rrIndex = (s.rrIndex + 1) % len(usable)
	s.mu.Unlock()

	var lastErr *client.UpstreamError
	for i := range len(usable) {
		idx := (startIdx + i) % len(usable)
		acct := usable[idx]

		ue := s.tryAccount(r.Context(), &acct, route, upstreamBody, req.Stream, w)
		if ue.Kind == client.KindOK {
			return
		}
		lastErr = ue

		// 410004 — akun ditolak permanen: karantina, jangan pernah dicoba lagi.
		if ue.ShouldDisableAccount() {
			s.quarantineAccount(acct, ue)
			continue
		}
		// Kesalahan request (model/body): akun lain tidak akan menolong.
		if ue.IsFatalForAllAccounts() {
			break
		}
		// WAF polos: beri jeda sebelum pindah akun.
		if ue.Kind == client.KindWAFBlocked {
			log.Printf("[autoclawpi] akun #%d WAF block, coba akun berikutnya", acct.ID)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		// Kuota model habis di akun ini — akun lain mungkin masih punya.
		if ue.Kind == client.KindQuotaExhausted {
			log.Printf("[autoclawpi] akun #%d kuota model habis (code=%d), coba akun berikutnya", acct.ID, ue.Code)
		}
	}

	s.writeUpstreamFailure(w, lastErr)
}

// filterUsableAccounts mengembalikan akun yang siap dipakai untuk inference.
//
// Sengaja TIDAK menyaring berdasarkan claim source_id token. Pengukuran
// langsung ke upstream (2026-09-15) menunjukkan source_id tidak menentukan
// apakah akun diterima: untuk satu akun yang sama, token ber-source_id
// autoclawaccess_token maupun agentaccess_token sama-sama ditolak 410004.
// Blokir 410004 adalah status akun di sisi server, bukan sifat token — jadi
// satu-satunya sinyal yang layak dipercaya adalah respons upstream itu sendiri
// (lihat quarantineAccount). Menyaring di sini hanya akan melewati akun yang
// sebenarnya sehat.
func filterUsableAccounts(accounts []db.Account) []db.Account {
	usable := make([]db.Account, 0, len(accounts))
	for _, a := range accounts {
		if !a.Active || a.AccessToken == "" {
			continue
		}
		usable = append(usable, a)
	}
	return usable
}

// tryAccount mengirim request ke satu akun, menangani refresh token (401) dan
// throttle (810002) dengan backoff. Mengembalikan klasifikasi hasil terakhir.
func (s *Server) tryAccount(ctx context.Context, acct *db.Account, route string, body []byte, stream bool, w http.ResponseWriter) *client.UpstreamError {
	const (
		maxThrottleRetries  = 3
		throttleBaseBackoff = 700 * time.Millisecond
	)
	refreshed := false
	throttles := 0

	for {
		status, _, raw, err := s.forward(ctx, *acct, route, body, stream, w)
		if err != nil {
			log.Printf("[autoclawpi] akun #%d error jaringan: %v", acct.ID, err)
			return &client.UpstreamError{Kind: client.KindUpstreamError, Message: err.Error()}
		}

		ue := client.Classify(status, raw)
		if ue.Kind == client.KindOK {
			return ue
		}

		switch ue.Kind {
		case client.KindTokenExpired:
			if refreshed {
				return ue
			}
			if _, rerr := s.refreshToken(acct); rerr != nil {
				log.Printf("[autoclawpi] akun #%d refresh gagal: %v", acct.ID, rerr)
				return ue
			}
			refreshed = true
			continue

		case client.KindThrottled:
			if throttles >= maxThrottleRetries {
				return ue
			}
			throttles++
			backoff := throttleBaseBackoff * time.Duration(1<<(throttles-1))
			log.Printf("[autoclawpi] akun #%d throttle (code=%d), retry %d/%d setelah %s",
				acct.ID, ue.Code, throttles, maxThrottleRetries, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ue
			}
			continue
		}

		return ue
	}
}

// quarantineAccount menonaktifkan akun yang ditolak permanen oleh upstream.
func (s *Server) quarantineAccount(acct db.Account, ue *client.UpstreamError) {
	log.Printf("[autoclawpi] akun #%d DIBLOKIR upstream (code=%d %s) — dinonaktifkan, tidak dicoba lagi",
		acct.ID, ue.Code, ue.Message)
	if err := db.SetAccountActive(acct.ID, false); err != nil {
		log.Printf("[autoclawpi] gagal menonaktifkan akun #%d: %v", acct.ID, err)
	}
}

// writeUpstreamFailure menerjemahkan kegagalan terakhir menjadi response OpenAI.
func (s *Server) writeUpstreamFailure(w http.ResponseWriter, lastErr *client.UpstreamError) {
	if lastErr == nil {
		writeOpenAIError(w, 503, "all_accounts_failed", "semua akun gagal memproses request")
		return
	}

	detail := fmt.Sprintf("upstream %d kind=%s code=%d: %s",
		lastErr.HTTPStatus, lastErr.Kind, lastErr.Code, lastErr.Message)

	switch {
	case lastErr.IsFatalForAllAccounts():
		writeOpenAIError(w, 400, "invalid_request_error", detail)
	case lastErr.Kind == client.KindAccountBanned:
		writeOpenAIError(w, 503, "all_accounts_banned",
			"semua akun tersedia diblokir upstream (410004 账号已被封禁). "+
				"Ini status akun di sisi AutoClaw — token baru/refresh tidak menolong. "+
				"Akun sudah dinonaktifkan otomatis; kalau upstream memulihkan, bật lại bằng "+
				"`autoclawpi account enable <id>`.")
	case lastErr.Kind == client.KindQuotaExhausted:
		writeOpenAIError(w, 429, "model_quota_exhausted",
			"kuota gratis model ini sudah habis di semua akun (810000); pakai model lain atau akun dengan langganan — "+detail)
	case lastErr.Kind == client.KindThrottled:
		writeOpenAIError(w, 429, "upstream_throttled",
			"upstream sedang membatasi permintaan (810002 pay-view), coba lagi nanti — "+detail)
	default:
		writeOpenAIError(w, 503, "all_accounts_failed", "semua akun gagal memproses request — "+detail)
	}
}

// forward mengirim request ke upstream dan menulis response ke klien.
// Untuk response non-streaming, membaca tubuh penuh dulu, parse token usage, lalu log.
// Untuk streaming, melewatkan data langsung tanpa log.
func (s *Server) forward(ctx context.Context, acct db.Account, route string, body []byte, stream bool, w http.ResponseWriter) (int, string, []byte, error) {
	baseURL := s.cl.InferenceBase
	if baseURL == "" {
		baseURL = "https://autoglm-api.autoglm.ai"
	}

	url := baseURL + "/autoclaw-proxy/proxy/autoclaw/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, fmt.Errorf("buat request: %w", err)
	}

	headers := s.cl.InferenceHeader(acct.AccessToken, route)
	headers["Content-Type"] = "application/json"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if stream {
		req.Header.Set("Accept", "text/event-stream")
	} else {
		req.Header.Set("Accept", "application/json")
	}

	resp, err := s.cl.Do(req)
	if err != nil {
		return 0, "", nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}

	if resp.StatusCode == 401 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp.StatusCode, ct, b, nil
	}

	if resp.StatusCode != 200 {
		// Upstream gagal (termasuk 403 WAF murni): jangan tulis apa pun
		// ke w. Handler akan mencoba akun berikutnya atau menulis respons
		// 503 final tepat satu kali — mencegah body terkonkatenasi dari
		// beberapa akun (superfluous WriteHeader). Body tetap di-log.
		rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		go logUsage(acct.ID, route, resp.StatusCode, rawBody)
		return resp.StatusCode, ct, rawBody, nil
	}

	w.Header().Set("Content-Type", ct)
	if stream {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(resp.StatusCode)
		flusher, _ := w.(http.Flusher)
		buf := make([]byte, 32*1024)
		first := true
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				data := buf[:n]
				// Buang prefix "forbidden" WAF yang kadang menempel di
				// depan body SSE stream yang sah.
				if first && data[0] == '{' && bytes.Contains(data, []byte(`"message":"forbidden"`)) {
					for i := 1; i < len(data); i++ {
						if data[i] == '{' {
							data = data[i:]
							break
						}
					}
				}
				if _, werr := w.Write(data); werr != nil {
					return resp.StatusCode, ct, nil, nil
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if rerr != nil {
				break
			}
			first = false
		}
		return resp.StatusCode, ct, nil, nil
	}

	// Non-streaming sukses: baca body, bersihkan, kirim, log.
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	cleaned := stripNonStandard(rawBody)
	if cleaned == nil || isWAFBlockOnly(cleaned) {
		// WAF block murni yang datang dengan status 200 — jangan tulis ke
		// klien; balikkan 403 agar handler mencoba akun berikutnya.
		if cleaned != nil {
			log.Printf("[autoclawpi] WAF hard block: %s", truncateResp(cleaned, 80))
		}
		return http.StatusForbidden, ct, rawBody, nil
	}
	if cleaned != nil {
		w.WriteHeader(resp.StatusCode)
		w.Write(cleaned)
	} else {
		w.WriteHeader(resp.StatusCode)
		w.Write(rawBody)
	}

	// Log token usage
	go logUsage(acct.ID, route, resp.StatusCode, rawBody)

	return resp.StatusCode, ct, nil, nil
}

// stripNonStandard removes non-OpenAI fields from chat completion response.
func stripNonStandard(body []byte) []byte {
	// Strip all WAF prefixes
	for {
		idx := bytes.Index(body, []byte(`"message":"forbidden"`))
		if idx < 0 {
			break
		}
		// Find the end of this forbidden object
		end := bytes.Index(body[idx+1:], []byte(`{`))
		if end < 0 {
			break
		}
		body = body[idx+end+1:]
	}
	if len(body) == 0 {
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}
	// Remove reasoning_content from choices
	if choices, ok := data["choices"].([]any); ok {
		for _, c := range choices {
			if choice, ok := c.(map[string]any); ok {
				if msg, ok := choice["message"].(map[string]any); ok {
					// Move reasoning_content to content if content is empty
					if content, _ := msg["content"].(string); content == "" {
						if reasoning, ok := msg["reasoning_content"].(string); ok && reasoning != "" {
							msg["content"] = reasoning[:min(len(reasoning), 500)]
						}
					}
					delete(msg, "reasoning_content")
				}
			}
		}
	}
	// Remove non-standard usage details
	if usage, ok := data["usage"].(map[string]any); ok {
		delete(usage, "completion_tokens_details")
		delete(usage, "prompt_tokens_details")
	}
	cleaned, _ := json.Marshal(data)
	return cleaned
}

// logUsage parse response body dan catat ke database.
// httpStatus: status code upstream asli (0 bila tidak ada — mis. error network).
func logUsage(acctID int64, model string, httpStatus int, body []byte) {
	for bytes.Contains(body, []byte(`"message":"forbidden"`)) {
		idx := bytes.Index(body, []byte(`"message":"forbidden"`))
		next := bytes.Index(body[idx+1:], []byte(`{`))
		if next < 0 {
			break
		}
		body = body[idx+next+1:]
	}
	var data struct {
		Usage *struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return
	}
	status := "success"
	errMsg := ""
	if httpStatus != 0 && httpStatus != 200 {
		// Kegagalan HTTP tanpa error JSON tetap tercatat — dulu
		// tercatat "success" dengan 0 token.
		status = "error"
		if data.Error != nil && data.Error.Message != "" {
			errMsg = data.Error.Message
		} else {
			errMsg = fmt.Sprintf("http %d", httpStatus)
		}
	} else if data.Error != nil {
		status = "error"
		errMsg = data.Error.Message
	}
	pts := 0
	cts := 0
	tts := 0
	if data.Usage != nil {
		pts = data.Usage.PromptTokens
		cts = data.Usage.CompletionTokens
		tts = data.Usage.TotalTokens
	}
	cost := float64(tts) * 0.001 / 1000.0
	_, _ = db.AddLog(&db.LogEntry{
		AccountID:        acctID,
		Model:            model,
		PromptTokens:     pts,
		CompletionTokens: cts,
		TotalTokens:      tts,
		Cost:             cost,
		Status:           status,
		Error:            errMsg,
	})
}

// handleModels menangani /v1/models.
// Daftar diambil dari katalog tunggal di package client supaya tidak ada
// dua sumber kebenaran yang bisa saling menyimpang.
func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request) {
	models := make([]map[string]any, 0, len(client.Catalog()))
	for _, m := range client.Catalog() {
		models = append(models, map[string]any{
			"id":       m.ID,
			"object":   "model",
			"created":  1,
			"owned_by": "autoclaw",
			"name":     m.Name,
			"route_id": m.RouteID,
		})
	}
	writeJSON(w, 200, map[string]any{"object": "list", "data": models})
}

// handleHealth menangani /healthz.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	accounts, _ := db.ListAccounts()
	activeCount := 0
	for _, a := range accounts {
		if a.Active {
			activeCount++
		}
	}
	writeJSON(w, 200, map[string]any{
		"ok":       true,
		"status":   "healthy",
		"accounts": len(accounts),
		"active":   activeCount,
		"time":     time.Now().Format(time.RFC3339),
	})
}

// refreshToken mencoba memperbarui token akun.
func (s *Server) refreshToken(acct *db.Account) (bool, error) {
	if acct.RefreshToken == "" {
		return false, fmt.Errorf("no refresh token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := s.cl.Refresh(ctx, acct.RefreshToken)
	if err != nil {
		return false, err
	}
	if out.Code != 0 || out.Data == nil || out.Data.AccessToken == "" {
		msg := "refresh gagal"
		if out != nil {
			msg = out.Msg
		}
		return false, fmt.Errorf("%s", msg)
	}
	newRefresh := acct.RefreshToken
	if out.Data.RefreshToken != "" {
		newRefresh = out.Data.RefreshToken
	}
	acct.AccessToken = out.Data.AccessToken
	acct.RefreshToken = newRefresh
	if err := db.UpdateAccountTokens(acct.ID, acct.AccessToken, acct.RefreshToken); err != nil {
		return false, fmt.Errorf("simpan token: %w", err)
	}
	log.Printf("[autoclawpi] akun #%d token diperbarui (source_id=%s)", acct.ID, tokenSourceOrUnknown(acct.AccessToken))
	return true, nil
}

// tokenSourceOrUnknown mengembalikan source_id token, atau "?" bila tak terbaca.
func tokenSourceOrUnknown(token string) string {
	if src := client.TokenSource(token); src != "" {
		return src
	}
	return "?"
}

// ── helpers ─────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeOpenAIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"message": message,
			"type":    code,
		},
	})
}

func replaceModel(raw []byte, model string) ([]byte, error) {
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	data["model"] = model
	return json.Marshal(data)
}

// isWAFBlockOnly checks if the response body is just a WAF block (no actual content).
func isWAFBlockOnly(body []byte) bool {
	if len(body) < 30 {
		return bytes.Contains(body, []byte(`"message":"forbidden"`))
	}
	return false
}

func truncateResp(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
