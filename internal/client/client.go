// Package client menyediakan HTTP client untuk API AutoClaw.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hirotomasato/autoclawpi/internal/sign"
)

// Client adalah HTTP client ke API AutoClaw.
type Client struct {
	mu            sync.RWMutex
	httpClient    *http.Client
	proxy         string
	InferenceBase string // https://autoglm-api.autoglm.ai/autoclaw-proxy/proxy/autoclaw
	UserAPIBase   string // https://autoglm-api.autoglm.ai
	Version       string
}

// New membuat client dengan default yang masuk akal.
func New(inferenceBase, userAPIBase string) *Client {
	return &Client{
		httpClient:    newHTTPClient(nil),
		InferenceBase: inferenceBase,
		UserAPIBase:   userAPIBase,
		Version:       "1.17.9",
	}
}

// deviceID mengembalikan ID perangkat persisten.
var deviceIDCache string

func deviceID() string {
	if deviceIDCache != "" {
		return deviceIDCache
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown"
	}
	b := make([]byte, 4)
	rand.Read(b)
	deviceIDCache = fmt.Sprintf("%s-%s", h, hex.EncodeToString(b))
	return deviceIDCache
}

// Do melakukan request dengan User-Agent aplikasi.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "AutoClaw/"+c.Version)
	c.mu.RLock()
	httpClient := c.httpClient
	c.mu.RUnlock()
	return httpClient.Do(req)
}

// SetProxy configures the shared outbound HTTP client. An empty value disables
// the application proxy and restores the default transport behavior.
func (c *Client) SetProxy(raw string) error {
	normalized, err := NormalizeProxy(raw)
	if err != nil {
		return err
	}
	var proxyURL *url.URL
	if normalized != "" {
		proxyURL, _ = url.Parse(normalized)
	}
	c.mu.Lock()
	c.httpClient = newHTTPClient(proxyURL)
	c.proxy = normalized
	c.mu.Unlock()
	return nil
}

// ProxyConfigured reports whether an application HTTP proxy is active.
func (c *Client) ProxyConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.proxy != ""
}

// ProxySummary returns a credential-safe proxy description for the web panel.
func (c *Client) ProxySummary() string {
	c.mu.RLock()
	proxy := c.proxy
	c.mu.RUnlock()
	if proxy == "" {
		return ""
	}
	u, err := url.Parse(proxy)
	if err != nil || u.Host == "" {
		return "configured"
	}
	if u.User != nil {
		u.User = url.UserPassword(u.User.Username(), "****")
	}
	return u.String()
}

// CheckProxy verifies that the configured outbound transport can reach the
// AutoClaw upstream. Any HTTP response proves the proxy connection succeeded.
func (c *Client) CheckProxy(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://autoglm-api.autoglm.ai/", nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4096)
	return resp.StatusCode, nil
}

// NormalizeProxy accepts an HTTP(S) proxy URL or host:port:user:pass.
func NormalizeProxy(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	proxyURL := raw
	if !strings.Contains(raw, "://") {
		parts := strings.Split(raw, ":")
		switch len(parts) {
		case 2:
			proxyURL = "http://" + raw
		case 4:
			if parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
				return "", fmt.Errorf("proxy must be in the form host:port:user:pass")
			}
			proxyURL = (&url.URL{
				Scheme: "http",
				Host:   net.JoinHostPort(parts[0], parts[1]),
				User:   url.UserPassword(parts[2], parts[3]),
			}).String()
		default:
			return "", fmt.Errorf("proxy must be an http(s) URL or host:port:user:pass")
		}
	}

	u, err := url.Parse(proxyURL)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Hostname() == "" || u.Port() == "" {
		return "", fmt.Errorf("invalid proxy URL")
	}
	return u.String(), nil
}

func newHTTPClient(proxyURL *url.URL) *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		transport = transport.Clone()
	} else {
		transport = &http.Transport{}
	}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Transport: transport, Timeout: 0}
}

// LoginResponse adalah payload balikan oauth login.
type LoginResponse struct {
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Trace string `json:"trace,omitempty"`
	Data  *struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		UserID       any    `json:"user_id,omitempty"`
		UserName     string `json:"user_name,omitempty"`
	} `json:"data,omitempty"`
}

// OAuthURL meminta URL OAuth. Return: url, state, error.
func (c *Client) OAuthURL(ctx context.Context, vendor, navigateURI, sourceID string, captcha map[string]any) (string, string, error) {
	ts := time.Now().Unix()
	body := map[string]any{
		"source_id":    sourceID,
		"navigate_uri": navigateURI,
		"device_id":    deviceID(),
	}
	if captcha != nil {
		for k, v := range captcha {
			body[k] = v
		}
	}
	if vendor == "google" {
		body["client_type"] = "pc"
	}
	var out struct {
		Code  int             `json:"code"`
		Msg   string          `json:"msg"`
		Trace string          `json:"trace"`
		Data  json.RawMessage `json:"data"`
	}
	if err := c.userapiPostWithHeaders(ctx, "/userapi/overseasv1/"+vendor+"-oauth-url", body, &out, sign.HeadersAt(ts)); err != nil {
		return "", "", err
	}
	if out.Code != 0 || out.Data == nil {
		return "", "", fmt.Errorf("oauth-url code=%d msg=%s trace=%s data=%s", out.Code, out.Msg, out.Trace, string(out.Data))
	}
	var urlData struct {
		OAuthURL string `json:"oauth_url"`
		State    string `json:"state"`
	}
	if err := json.Unmarshal(out.Data, &urlData); err != nil || urlData.OAuthURL == "" {
		return "", "", fmt.Errorf("oauth-url code=%d msg=%s trace=%s data=%s (url parse: %v)", out.Code, out.Msg, out.Trace, string(out.Data), err)
	}
	return urlData.OAuthURL, urlData.State, nil
}

// CaptchaConfig mengambil konfigurasi captcha OAuth.
func (c *Client) CaptchaConfig(ctx context.Context) (*CaptchaConfigResponse, error) {
	var out CaptchaConfigResponse
	if err := c.userapiPost(ctx, "/userapi/overseasv1/oauth-captcha-config", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CaptchaConfigResponse adalah balikan oauth-captcha-config.
type CaptchaConfigResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data *struct {
		Enabled  bool   `json:"enabled"`
		Region   string `json:"region"`
		Prefix   string `json:"prefix"`
		SceneID  string `json:"scene_id"`
		Supplier string `json:"captcha_supplier"`
	} `json:"data"`
}

// OAuthURLVerbose meminta URL OAuth dan melaporkan apakah captcha wajib.
func (c *Client) OAuthURLVerbose(ctx context.Context, vendor, navigateURI, sourceID string) (string, bool, error) {
	url, _, err := c.OAuthURL(ctx, vendor, navigateURI, sourceID, nil)
	if err == nil {
		return url, false, nil
	}
	return "", true, nil
}

// Login menukar kode OAuth jadi access/refresh token.
func (c *Client) Login(ctx context.Context, vendor, code, state, navigateURI string) (*LoginResponse, error) {
	body := map[string]any{
		"code":         code,
		"state":        state,
		"navigate_uri": navigateURI,
		"device_id":    deviceID(),
		"source_id":    "autoclaw",
	}
	var out LoginResponse
	if err := c.userapiPost(ctx, "/userapi/overseasv1/"+vendor+"-oauth-login", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Refresh memperbarui access token pakai refresh token.
//
// Memakai /userapi/v1/refresh — endpoint yang dipakai app AutoClaw sendiri.
// Ada endpoint lain, /userapi/v1/agent-refresh, yang juga mengembalikan
// code:0 dan token yang sah; keduanya berfungsi, tetapi mencocokkan app resmi
// lebih kecil risikonya terhadap perubahan upstream. Fallback ke agent-refresh
// bila endpoint utama tidak tersedia, supaya tidak ada regresi.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	body := map[string]any{
		"refresh_token": refreshToken,
		"device_id":     deviceID(),
		"source_id":     "autoclaw",
	}

	var out LoginResponse
	err := c.userapiPost(ctx, "/userapi/v1/refresh", body, &out)
	if err == nil && out.Code == 0 && out.Data != nil && out.Data.AccessToken != "" {
		return &out, nil
	}

	fallback := LoginResponse{}
	if ferr := c.userapiPost(ctx, "/userapi/v1/agent-refresh", body, &fallback); ferr != nil {
		if err != nil {
			return nil, err
		}
		return nil, ferr
	}
	return &fallback, nil
}

// ClaimTask mengklaim task check-in (daily_signin, dll).
// Token harus sudah include "Bearer " prefix.
func (c *Client) ClaimTask(ctx context.Context, token, taskID string) (int, bool, error) {
	hdrs := c.InferenceHeader(token, "")
	// Tambah header yang diperlukan userapi
	hdrs["X-Lang"] = "en"
	hdrs["X-Client-Type"] = "pc"
	hdrs["authorization"] = token   // lowercase untuk userapi
	delete(hdrs, "X-Authorization") // inference header gak dipake

	body := fmt.Sprintf(`{"task_id":"%s"}`, taskID)
	req, err := http.NewRequestWithContext(ctx, "POST",
		c.UserAPIBase+"/autoclaw-proxy/proxy/autoclaw-task-complete",
		strings.NewReader(body))
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}

	resp, err := c.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var result struct {
		Data *struct {
			Success         bool `json:"success"`
			AlreadyComplete bool `json:"already_completed"`
			RewardPoints    int  `json:"reward_points"`
		} `json:"data"`
	}
	json.Unmarshal(b, &result)

	if result.Data == nil {
		return 0, false, fmt.Errorf("response: %s", string(b))
	}
	if result.Data.AlreadyComplete {
		return 0, true, nil // already done
	}
	if !result.Data.Success {
		return 0, false, fmt.Errorf("server: success=false")
	}
	return result.Data.RewardPoints, false, nil
}

// ClaimNewbieToken mengklaim token newbie guide (reward 100M token untuk akun baru).
// Endpoint ini pakai header X-Authorization (uppercase, mirip inference proxy),
// BUKAN commonHeaders userapi — tanpa signature X-Auth-*.
// Body kosong. Return token guide (base64 user_id|timestamp|signature).
func (c *Client) ClaimNewbieToken(ctx context.Context, accessToken string) (string, error) {
	tok := accessToken
	if !strings.HasPrefix(tok, "Bearer ") {
		tok = "Bearer " + tok
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.UserAPIBase+"/autoclaw-proxy/proxy/autoclaw-newbie-guide/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Authorization", tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(b, 300))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("payload bukan JSON: %s", truncate(b, 200))
	}
	if out.Token == "" {
		return "", fmt.Errorf("token kosong: %s", truncate(b, 300))
	}
	return out.Token, nil
}

// ClaimPromotionReward mengklaim reward promosi (modal_id + reward_type).
// Header X-Authorization sama kayak ClaimNewbieToken.
func (c *Client) ClaimPromotionReward(ctx context.Context, accessToken, modalID, rewardType string) (json.RawMessage, error) {
	tok := accessToken
	if !strings.HasPrefix(tok, "Bearer ") {
		tok = "Bearer " + tok
	}
	body, _ := json.Marshal(map[string]string{
		"modal_id":    modalID,
		"reward_type": rewardType,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.UserAPIBase+"/autoclaw-proxy/proxy/autoclaw-promotion-reward", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Authorization", tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(b, 300))
	}
	return json.RawMessage(b), nil
}

func (c *Client) userapiPost(ctx context.Context, path string, body any, out any) error {
	return c.userapiPostWithHeaders(ctx, path, body, out, sign.Headers())
}

func (c *Client) userapiPostWithHeaders(ctx context.Context, path string, body any, out any, hdrs map[string]string) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.UserAPIBase+path, &buf)
	if err != nil {
		return err
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	// Add common headers (authorization with token, X-Lang, etc.)
	req.Header.Set("X-Lang", "en")
	req.Header.Set("X-Client-Type", "pc")
	// Note: Token is NOT added here - it's only used for inference and agentdr endpoints
	return c.doJSON(req, out)
}

func (c *Client) doJSON(req *http.Request, out any) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("HTTP %d: payload bukan JSON: %s", resp.StatusCode, truncate(b, 200))
		}
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(b, 300))
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

// InferenceHeader membangun header untuk proxy inference.
func (c *Client) InferenceHeader(accessToken, routeModelID string) map[string]string {
	tok := accessToken
	if !strings.HasPrefix(tok, "Bearer ") {
		tok = "Bearer " + tok
	}
	return map[string]string{
		"X-Authorization": tok,
		"X-Request-Id":    sign.UUID(),
		"X-Request-Model": routeModelID,
		"X-Product":       "autoclaw",
		"X-Harness-Type":  "zcode",
		"X-Tm":            "win",
		"X-Version":       c.Version,
		"X-Lang":          "id",
		"x_trace_id":      sign.UUID(),
	}
}

// ModelInfo mendeskripsikan satu model yang dipublikasikan proxy.
type ModelInfo struct {
	ID            string // nama OpenAI-style yang dipakai klien
	RouteID       string // X-Request-Model yang dikirim ke upstream
	Name          string // label manusia
	ContextWindow int
	MaxTokens     int
}

// modelCatalog adalah satu-satunya sumber kebenaran untuk daftar model.
//
// Diverifikasi langsung ke upstream (2026-09-15): setiap RouteID di bawah
// mengembalikan HTTP 200, sedangkan "zai_glm-5-turbo" mengembalikan
// 400 {"message":"非法模型"}. RouteID juga harus cocok dengan
// ~/.openclaw-autoclaw/openclaw.runtime.json → models.providers.zai.models[].id
// pada app yang terpasang; kalau app di-update, sinkronkan ulang dari sana.
var modelCatalog = []ModelInfo{
	{ID: "auto", RouteID: "zai_auto", Name: "Auto", ContextWindow: 1048576, MaxTokens: 131072},
	{ID: "auto-fast", RouteID: "zai_auto-fast", Name: "Auto-Fast", ContextWindow: 1048576, MaxTokens: 393216},
	{ID: "glm-5.3", RouteID: "zaicoding_glm-5.3", Name: "GLM-5.3", ContextWindow: 1048576, MaxTokens: 307200},
	{ID: "glm-5.3-flash", RouteID: "zai_glm-5.3-flash", Name: "GLM-5.3-Flash", ContextWindow: 1048576, MaxTokens: 131072},
	{ID: "deepseek-v4-pro", RouteID: "tdpsk_deepseek-v4-pro-202606", Name: "DeepSeek-V4-Pro", ContextWindow: 1048576, MaxTokens: 393216},
	{ID: "deepseek-v4-flash", RouteID: "tdpsk_deepseek-v4-flash-202605", Name: "DeepSeek-V4.1-Flash", ContextWindow: 1048576, MaxTokens: 393216},
}

// Catalog mengembalikan salinan katalog model yang didukung.
func Catalog() []ModelInfo {
	out := make([]ModelInfo, len(modelCatalog))
	copy(out, modelCatalog)
	return out
}

// SupportedModels adalah catalog OpenAI-style yang dipublikasikan oleh proxy.
func SupportedModels() []string {
	out := make([]string, 0, len(modelCatalog))
	for _, m := range modelCatalog {
		out = append(out, m.ID)
	}
	return out
}

// ProfileStatus adalah hasil pemeriksaan status akun di userapi.
//
// Endpoint ini menjawab dengan HTTP 200 walau akun diblokir, jadi kode bisnis
// di body yang harus dibaca — bukan status HTTP.
type ProfileStatus struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

// Banned melaporkan apakah akun ditolak permanen oleh AutoClaw.
func (p *ProfileStatus) Banned() bool {
	return p != nil && p.Code == 410004
}

// UserProfile memeriksa status akun lewat /userapi/v1/user-profile.
//
// Ini cara termurah dan paling pasti untuk tahu apakah sebuah akun masih
// hidup: jauh lebih baik daripada menembak endpoint inference dan menebak
// dari kode galatnya. Respons 410004 di sini berarti "User banned" — status
// akun di sisi AutoClaw yang tidak bisa diperbaiki dari sisi klien.
func (c *Client) UserProfile(ctx context.Context, accessToken string) (*ProfileStatus, error) {
	if accessToken == "" {
		return nil, fmt.Errorf("access token kosong")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.UserAPIBase, "/")+"/userapi/v1/user-profile",
		strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	for k, v := range sign.Headers() {
		req.Header.Set(k, v)
	}
	tok := strings.TrimSpace(accessToken)
	if !strings.HasPrefix(tok, "Bearer ") {
		tok = "Bearer " + tok
	}
	req.Header.Set("authorization", tok)
	req.Header.Set("X-Lang", "en")
	req.Header.Set("X-Client-Type", "pc")

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out ProfileStatus
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("HTTP %d: payload bukan JSON: %s", resp.StatusCode, truncate(raw, 200))
	}
	return &out, nil
}

// RouteID memetakan nama model OpenAI-style ke route id AutoClaw.
// Nama yang sudah berupa route id (mengandung "_") dikembalikan apa adanya.
func RouteID(model string) string {
	if containsUnderscore(model) {
		return model // sudah route id
	}
	for _, m := range modelCatalog {
		if m.ID == model {
			return m.RouteID
		}
	}
	// Di luar katalog: teruskan apa adanya, biar upstream yang memutuskan.
	// Hasilnya akan terklasifikasi sebagai invalid_model.
	return model
}

// KnownModel melaporkan apakah nama model (atau route id) ada di katalog.
func KnownModel(model string) bool {
	if containsUnderscore(model) {
		for _, m := range modelCatalog {
			if m.RouteID == model {
				return true
			}
		}
		return false
	}
	for _, m := range modelCatalog {
		if m.ID == model {
			return true
		}
	}
	return false
}

// BodyModel membalik RouteID: "zaicoding_glm-5.3" -> "glm-5.3".
func BodyModel(routeID string) string {
	for i := 0; i < len(routeID); i++ {
		if routeID[i] == '_' {
			return routeID[i+1:]
		}
	}
	return routeID
}

func containsUnderscore(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '_' {
			return true
		}
	}
	return false
}
