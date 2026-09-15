package client

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// makeJWT membuat JWT tanpa tanda tangan yang sah, cukup untuk menguji
// pembacaan claim. Signature tidak pernah diverifikasi oleh package ini.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc(payload) + "." + enc([]byte("sig"))
}

func TestParseTokenClaims(t *testing.T) {
	exp := time.Now().Add(8 * time.Hour).Unix()
	tok := makeJWT(t, map[string]any{
		"user_id":   149387,
		"device_id": "c05a21bffeac2ac9",
		"source_id": SourceAutoClawAccess,
		"jti":       "boxuong.vohinh@gmail.com",
		"exp":       exp,
	})

	claims, err := ParseTokenClaims(tok)
	if err != nil {
		t.Fatalf("ParseTokenClaims error = %v", err)
	}
	if claims.UserID != 149387 {
		t.Errorf("UserID = %d, want 149387", claims.UserID)
	}
	if claims.SourceID != SourceAutoClawAccess {
		t.Errorf("SourceID = %q, want %q", claims.SourceID, SourceAutoClawAccess)
	}
	if claims.Subject != "boxuong.vohinh@gmail.com" {
		t.Errorf("Subject = %q", claims.Subject)
	}
}

func TestParseTokenClaimsAcceptsBearerPrefix(t *testing.T) {
	tok := makeJWT(t, map[string]any{"source_id": SourceAutoClawAccess})
	if _, err := ParseTokenClaims("Bearer " + tok); err != nil {
		t.Fatalf("harus menerima prefix Bearer: %v", err)
	}
}

func TestParseTokenClaimsRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"kosong", ""},
		{"bukan jwt", "abc"},
		{"payload bukan base64", "aaa.!!!.ccc"},
		{"payload bukan json", "aaa." + base64.RawURLEncoding.EncodeToString([]byte("bukan json")) + ".ccc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseTokenClaims(tt.in); err == nil {
				t.Fatalf("ParseTokenClaims(%q) harus error", tt.in)
			}
		})
	}
}

func TestTokenSourceAndAgentDetection(t *testing.T) {
	agent := makeJWT(t, map[string]any{"source_id": SourceAgentAccess})
	oauth := makeJWT(t, map[string]any{"source_id": SourceAutoClawAccess})

	if !IsAgentAccessToken(agent) {
		t.Error("token agent-access harus terdeteksi")
	}
	if IsAgentAccessToken(oauth) {
		t.Error("token OAuth tidak boleh dianggap agent-access")
	}
	if got := TokenSource(oauth); got != SourceAutoClawAccess {
		t.Errorf("TokenSource = %q, want %q", got, SourceAutoClawAccess)
	}
	// Token rusak tidak boleh diklaim agent-access (fail-open ke "coba dulu").
	if IsAgentAccessToken("bukan-jwt") {
		t.Error("token rusak tidak boleh diklasifikasi agent-access")
	}
	if got := TokenSource("bukan-jwt"); got != "" {
		t.Errorf("TokenSource(token rusak) = %q, want kosong", got)
	}
}

func TestTokenExpiry(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	tok := makeJWT(t, map[string]any{"exp": exp.Unix()})
	got, err := TokenExpiry(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(exp) {
		t.Errorf("TokenExpiry = %v, want %v", got, exp)
	}
}

func TestTokenSourceHint(t *testing.T) {
	if h := TokenSourceHint(makeJWT(t, map[string]any{"source_id": SourceAgentAccess})); h == "" {
		t.Error("hint tidak boleh kosong")
	}
}
