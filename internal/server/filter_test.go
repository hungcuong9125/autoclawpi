package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hirotomasato/autoclawpi/internal/client"
	"github.com/hirotomasato/autoclawpi/internal/db"
)

func jwtWithSource(t *testing.T, source string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"source_id": source, "user_id": 1})
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return enc([]byte(`{"alg":"HS256"}`)) + "." + enc(payload) + "." + enc([]byte("sig"))
}

// filterUsableAccounts sengaja TIDAK menyaring berdasarkan source_id token.
//
// Pengukuran langsung ke upstream menunjukkan satu akun yang sama ditolak
// 410004 baik dengan token autoclawaccess_token maupun agentaccess_token,
// jadi source_id bukan sinyal yang layak dipakai untuk membuang akun.
func TestFilterUsableAccountsKeepsEveryActiveAccount(t *testing.T) {
	accounts := []db.Account{
		{ID: 1, Active: true, AccessToken: jwtWithSource(t, client.SourceAgentAccess)},
		{ID: 2, Active: true, AccessToken: jwtWithSource(t, client.SourceAutoClawAccess)},
		{ID: 3, Active: false, AccessToken: jwtWithSource(t, client.SourceAutoClawAccess)},
		{ID: 4, Active: true, AccessToken: ""},
	}

	usable := filterUsableAccounts(accounts)
	if len(usable) != 2 {
		t.Fatalf("usable = %d akun, want 2 (aktif + punya token)", len(usable))
	}
	for _, a := range usable {
		if a.ID != 1 && a.ID != 2 {
			t.Errorf("akun #%d tidak seharusnya lolos", a.ID)
		}
	}
}

func TestFilterUsableAccountsSkipsInactiveAndEmptyToken(t *testing.T) {
	accounts := []db.Account{
		{ID: 1, Active: false, AccessToken: jwtWithSource(t, client.SourceAutoClawAccess)},
		{ID: 2, Active: true, AccessToken: ""},
	}
	if got := filterUsableAccounts(accounts); len(got) != 0 {
		t.Fatalf("usable = %+v, want kosong", got)
	}
}

func TestWriteUpstreamFailureMapsStatus(t *testing.T) {
	tests := []struct {
		name       string
		ue         *client.UpstreamError
		wantStatus int
	}{
		{"banned", &client.UpstreamError{HTTPStatus: 403, Code: 410004, Kind: client.KindAccountBanned}, 503},
		{"throttled", &client.UpstreamError{HTTPStatus: 403, Code: 810002, Kind: client.KindThrottled}, 429},
		{"invalid model", &client.UpstreamError{HTTPStatus: 400, Kind: client.KindInvalidModel}, 400},
		{"nil", nil, 503},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &fakeResponseWriter{}
			s := &Server{}
			s.writeUpstreamFailure(w, tt.ue)
			if w.status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.status, tt.wantStatus)
			}
		})
	}
}

// fakeResponseWriter cukup untuk memverifikasi status code yang ditulis.
type fakeResponseWriter struct {
	header http.Header
	status int
	body   []byte
}

func (f *fakeResponseWriter) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}
func (f *fakeResponseWriter) WriteHeader(code int) { f.status = code }
func (f *fakeResponseWriter) Write(b []byte) (int, error) {
	f.body = append(f.body, b...)
	return len(b), nil
}
