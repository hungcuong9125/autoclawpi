package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Source ID yang muncul di claim "source_id" của access token AutoClaw.
//
//	autoclawaccess_token — token hasil OAuth flow thật (app/web login).
//	agentaccess_token    — token hasil /userapi/v1/agent-refresh atau jalur
//	                       agent API. AutoClaw menandai token jenis ini dan
//	                       menolaknya di endpoint inference dengan 410004.
const (
	SourceAutoClawAccess = "autoclawaccess_token"
	SourceAgentAccess    = "agentaccess_token"
)

// TokenClaims adalah subset claim JWT yang dipakai autoclawpi.
type TokenClaims struct {
	UserID    int64  `json:"user_id"`
	DeviceID  string `json:"device_id"`
	SourceID  string `json:"source_id"`
	Subject   string `json:"jti"` // biasanya email
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// ParseTokenClaims mendekode payload JWT tanpa verifikasi tanda tangan.
// Signature tidak diverifikasi karena kita tidak memegang kunci AutoClaw —
// fungsi ini hanya untuk introspeksi/diagnostik, bukan untuk otorisasi.
func ParseTokenClaims(accessToken string) (*TokenClaims, error) {
	raw := strings.TrimSpace(accessToken)
	raw = strings.TrimPrefix(raw, "Bearer ")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("token kosong")
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token bukan JWT (segment=%d)", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Sebagian issuer memakai padding standar.
		padded := parts[1]
		if m := len(padded) % 4; m != 0 {
			padded += strings.Repeat("=", 4-m)
		}
		payload, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return nil, fmt.Errorf("decode payload: %w", err)
		}
	}

	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return &claims, nil
}

// TokenSource mengembalikan claim source_id dari access token.
// String kosong dikembalikan bila token tidak bisa dibaca.
func TokenSource(accessToken string) string {
	claims, err := ParseTokenClaims(accessToken)
	if err != nil {
		return ""
	}
	return claims.SourceID
}

// TokenExpiry mengembalikan waktu kedaluwarsa token.
func TokenExpiry(accessToken string) (time.Time, error) {
	claims, err := ParseTokenClaims(accessToken)
	if err != nil {
		return time.Time{}, err
	}
	if claims.ExpiresAt == 0 {
		return time.Time{}, fmt.Errorf("token tidak punya claim exp")
	}
	return time.Unix(claims.ExpiresAt, 0), nil
}

// IsAgentAccessToken melaporkan apakah token berasal dari jalur agent-access.
// Token jenis ini sudah terbukti ditolak upstream dengan 410004.
func IsAgentAccessToken(accessToken string) bool {
	return TokenSource(accessToken) == SourceAgentAccess
}

// TokenSourceHint mengembalikan penjelasan singkat untuk log/panel.
func TokenSourceHint(accessToken string) string {
	switch TokenSource(accessToken) {
	case SourceAutoClawAccess:
		return "OAuth flow (dapat dipakai inference)"
	case SourceAgentAccess:
		return "agent-access (ditolak upstream dengan 410004 — login ulang via OAuth)"
	case "":
		return "tidak terbaca"
	default:
		return TokenSource(accessToken)
	}
}
