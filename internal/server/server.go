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

	route := client.RouteID(req.Model)
	upstreamBody, err := replaceModel(raw, client.BodyModel(route))
	if err != nil {
		writeOpenAIError(w, 400, "invalid_request_error", "gagal olah body: "+err.Error())
		return
	}

	// Round-robin: coba setiap akun hingga salah satu berhasil
	accounts, _ := db.ListAccounts()
	if len(accounts) == 0 {
		writeOpenAIError(w, 503, "no_accounts", "tidak ada akun tersedia")
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
	startIdx := s.rrIndex % len(accounts)
	s.rrIndex = (s.rrIndex + 1) % len(accounts)
	s.mu.Unlock()

	var lastStatus int
	for i := range len(accounts) {
		idx := (startIdx + i) % len(accounts)
		acct := accounts[idx]
		if !acct.Active || acct.AccessToken == "" {
			continue
		}

		var ferr error
		lastStatus, _, _, ferr = s.forward(r.Context(), acct, route, upstreamBody, req.Stream, w)
		if ferr != nil {
			log.Printf("[autoclawpi] akun #%d error: %v", acct.ID, ferr)
			continue
		}
		// 401 — token expired, coba refresh
		if lastStatus == 401 {
			refreshed, rerr := s.refreshToken(&acct)
			if rerr != nil {
				log.Printf("[autoclawpi] akun #%d refresh gagal: %v", acct.ID, rerr)
				continue
			}
			// Retry dengan token baru
			var ferr2 error
			lastStatus, _, _, ferr2 = s.forward(r.Context(), acct, route, upstreamBody, req.Stream, w)
			if ferr2 != nil {
				log.Printf("[autoclawpi] akun #%d retry error: %v", acct.ID, ferr2)
				continue
			}
			_ = refreshed
			if lastStatus == 200 {
				return
			}
			continue
		}
		// 403 — WAF block, coba akun berikutnya
		if lastStatus == 403 {
			log.Printf("[autoclawpi] akun #%d WAF block, coba akun berikutnya", acct.ID)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if lastStatus == 200 {
			return
		}
		// Status lain (4xx, 5xx) — coba akun berikutnya
	}

	// Semua akun gagal — sertakan status upstream terakhir untuk diagnosis
	writeOpenAIError(w, 503, "all_accounts_failed", fmt.Sprintf("semua akun gagal memproses request (last_status=%d)", lastStatus))
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
		go logUsage(acct.ID, route, rawBody)
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
	go logUsage(acct.ID, route, rawBody)

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
func logUsage(acctID int64, model string, body []byte) {
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
	if data.Error != nil {
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
func (s *Server) handleModels(w http.ResponseWriter, _ *http.Request) {
	// Model yang sudah diverifikasi bisa inference (2026-09-05).
	models := []map[string]any{
		{"id": "auto", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "auto-fast", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "glm-5-turbo", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "glm-5.3", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "glm-5.3-flash", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "deepseek-v4-pro", "object": "model", "created": 1, "owned_by": "autoclaw"},
		{"id": "deepseek-v4-flash", "object": "model", "created": 1, "owned_by": "autoclaw"},
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
	_ = db.UpdateAccount(acct)
	log.Printf("[autoclawpi] akun #%d token diperbarui", acct.ID)
	return true, nil
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
