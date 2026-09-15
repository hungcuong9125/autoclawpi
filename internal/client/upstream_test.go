package client

import (
	"net/http"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantKind    ErrorKind
		wantCode    int
		disable     bool
		retrySame   bool
		fatalForAll bool
	}{
		{
			name:     "sukses",
			status:   200,
			body:     `{"choices":[]}`,
			wantKind: KindOK,
		},
		{
			name:      "410004 akun diblokir",
			status:    403,
			body:      `{"code":410004,"message":"账号已被封禁"}`,
			wantKind:  KindAccountBanned,
			wantCode:  410004,
			disable:   true,
			retrySame: false,
		},
		{
			name:      "810000 kuota model habis",
			status:    403,
			body:      `{"code":810000,"message":"GLM-5.3 free quota used up. Subscribe to a membership to continue."}`,
			wantKind:  KindQuotaExhausted,
			wantCode:  810000,
			disable:   false,
			retrySame: false, // kuota habis: akun lain mungkin masih punya
		},
		{
			name:      "810002 pay-view throttle",
			status:    403,
			body:      `{"action":{"kind":"pay-view"},"code":810002,"image_url":"https://x/y.png"}`,
			wantKind:  KindThrottled,
			wantCode:  810002,
			retrySame: true,
		},
		{
			name:      "pay-view tanpa code",
			status:    403,
			body:      `{"action":{"kind":"pay-view"}}`,
			wantKind:  KindThrottled,
			retrySame: true,
		},
		{
			name:      "401 token kedaluwarsa",
			status:    401,
			body:      `{"message":"unauthorized"}`,
			wantKind:  KindTokenExpired,
			retrySame: true, // refresh lalu ulangi akun yang sama
		},
		{
			name:        "400 model tidak dikenal",
			status:      400,
			body:        `{"message":"非法模型"}`,
			wantKind:    KindInvalidModel,
			fatalForAll: true,
		},
		{
			name:        "400 request tidak valid",
			status:      400,
			body:        `{"message":"invalid request"}`,
			wantKind:    KindBadRequest,
			fatalForAll: true, // akun lain tidak akan menolong request yang salah
		},
		{
			name:     "403 WAF polos",
			status:   403,
			body:     `{"message":"forbidden"}`,
			wantKind: KindWAFBlocked,
		},
		{
			name:     "500 upstream error",
			status:   500,
			body:     `{"message":"boom"}`,
			wantKind: KindUpstreamError,
		},
		{
			name:     "body kosong",
			status:   502,
			body:     ``,
			wantKind: KindUpstreamError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ue := Classify(tt.status, []byte(tt.body))
			if ue.Kind != tt.wantKind {
				t.Fatalf("Kind = %s, want %s", ue.Kind, tt.wantKind)
			}
			if tt.wantCode != 0 && ue.Code != tt.wantCode {
				t.Fatalf("Code = %d, want %d", ue.Code, tt.wantCode)
			}
			if ue.ShouldDisableAccount() != tt.disable {
				t.Errorf("ShouldDisableAccount = %v, want %v", ue.ShouldDisableAccount(), tt.disable)
			}
			if ue.ShouldRetrySameAccount() != tt.retrySame {
				t.Errorf("ShouldRetrySameAccount = %v, want %v", ue.ShouldRetrySameAccount(), tt.retrySame)
			}
			if ue.IsFatalForAllAccounts() != tt.fatalForAll {
				t.Errorf("IsFatalForAllAccounts = %v, want %v", ue.IsFatalForAllAccounts(), tt.fatalForAll)
			}
		})
	}
}

// Regresi inti: 410004, 810000, dan 810002 semuanya 403, tapi tindakannya
// berbeda-beda. Sebelumnya ketiganya diperlakukan sebagai "WAF block" lalu
// di-failover tanpa membedakan akun mati vs kuota habis vs throttle.
func TestBannedQuotaAndThrottleAreDistinct(t *testing.T) {
	banned := Classify(http.StatusForbidden, []byte(`{"code":410004,"message":"账号已被封禁"}`))
	quota := Classify(http.StatusForbidden, []byte(`{"code":810000,"message":"free quota used up"}`))
	throttled := Classify(http.StatusForbidden, []byte(`{"code":810002,"message":"pay-view"}`))

	if banned.Kind == quota.Kind || quota.Kind == throttled.Kind || banned.Kind == throttled.Kind {
		t.Fatalf("tiga kode 403 harus diklasifikasi berbeda: %s / %s / %s", banned.Kind, quota.Kind, throttled.Kind)
	}
	if !banned.ShouldDisableAccount() {
		t.Error("410004 harus menonaktifkan akun")
	}
	if quota.ShouldDisableAccount() {
		t.Error("810000 tidak boleh menonaktifkan akun — akun masih bisa dipakai model lain")
	}
	if throttled.ShouldDisableAccount() {
		t.Error("810002 tidak boleh menonaktifkan akun — hanya throttle sementara")
	}
	if !throttled.ShouldRetrySameAccount() {
		t.Error("810002 harus di-retry ke akun yang sama")
	}
	if quota.ShouldRetrySameAccount() {
		t.Error("810000 tidak perlu di-retry ke akun yang sama — kuotanya sudah habis")
	}
}

func TestIsWAFForbiddenBody(t *testing.T) {
	if !IsWAFForbiddenBody([]byte(`{"message":"forbidden"}`)) {
		t.Error("body forbidden harus terdeteksi")
	}
	if IsWAFForbiddenBody([]byte(`{"choices":[]}`)) {
		t.Error("body inference normal tidak boleh dianggap WAF")
	}
	if IsWAFForbiddenBody(nil) {
		t.Error("body kosong bukan WAF")
	}
}
