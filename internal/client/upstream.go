package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Kode error bisnis AutoClaw yang perlu ditangani berbeda-beda.
//
// Sebelumnya semua 403 diperlakukan sama ("WAF block") sehingga akun yang
// benar-benar diblokir (410004) dicoba berulang kali tanpa hasil, dan
// throttle sementara (810002) ikut dibuang padahal cukup di-retry.
const (
	CodeAccountBanned  = 410004 // 账号已被封禁 — akun ditandai auto-register
	CodeQuotaExhausted = 810000 // quota gratis model ini habis (per model)
	CodePayView        = 810002 // pay-view — throttle/quota sementara
)

// ErrorKind adalah klasifikasi tindakan yang harus diambil proxy.
type ErrorKind int

const (
	KindUnknown        ErrorKind = iota
	KindOK                       // 2xx
	KindTokenExpired             // 401 — refresh lalu retry sekali
	KindAccountBanned            // 410004 — nonaktifkan akun, jangan retry
	KindQuotaExhausted           // 810000 — kuota model habis; akun lain mungkin punya
	KindThrottled                // 810002 — retry dengan backoff
	KindInvalidModel             // 400 非法模型 — kesalahan request, gagal cepat
	KindBadRequest               // 400 lain — kesalahan request, gagal cepat
	KindWAFBlocked               // 403 forbidden polos — backoff lalu akun lain
	KindUpstreamError            // 5xx — akun lain
)

// String membuat ErrorKind mudah dibaca di log.
func (k ErrorKind) String() string {
	switch k {
	case KindOK:
		return "ok"
	case KindTokenExpired:
		return "token_expired"
	case KindAccountBanned:
		return "account_banned"
	case KindQuotaExhausted:
		return "quota_exhausted"
	case KindThrottled:
		return "throttled"
	case KindInvalidModel:
		return "invalid_model"
	case KindBadRequest:
		return "bad_request"
	case KindWAFBlocked:
		return "waf_blocked"
	case KindUpstreamError:
		return "upstream_error"
	default:
		return "unknown"
	}
}

// UpstreamError adalah hasil klasifikasi satu response upstream.
type UpstreamError struct {
	HTTPStatus int
	Code       int    // kode bisnis upstream (0 bila tidak ada)
	Message    string // pesan upstream
	Kind       ErrorKind
	Body       []byte
}

// Error memenuhi interface error.
func (e *UpstreamError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("upstream %d code=%d (%s): %s", e.HTTPStatus, e.Code, e.Kind, e.Message)
	}
	return fmt.Sprintf("upstream %d (%s): %s", e.HTTPStatus, e.Kind, e.Message)
}

// ShouldDisableAccount melaporkan apakah akun harus dinonaktifkan permanen.
func (e *UpstreamError) ShouldDisableAccount() bool {
	return e.Kind == KindAccountBanned
}

// ShouldRetrySameAccount melaporkan apakah request layak diulang ke akun yang sama.
func (e *UpstreamError) ShouldRetrySameAccount() bool {
	return e.Kind == KindThrottled || e.Kind == KindTokenExpired
}

// IsFatalForAllAccounts melaporkan apakah mencoba akun lain tidak akan menolong,
// karena masalahnya ada di request (bukan di akun).
func (e *UpstreamError) IsFatalForAllAccounts() bool {
	return e.Kind == KindInvalidModel || e.Kind == KindBadRequest
}

// envelope adalah bentuk umum body error AutoClaw.
type envelope struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Msg     string `json:"msg"`
	Action  *struct {
		Kind string `json:"kind"`
	} `json:"action"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Classify mengubah (status, body) upstream menjadi UpstreamError yang sudah
// diklasifikasi. body boleh nil.
func Classify(status int, body []byte) *UpstreamError {
	e := &UpstreamError{HTTPStatus: status, Body: body}

	if status >= 200 && status < 300 {
		e.Kind = KindOK
		return e
	}

	var env envelope
	_ = json.Unmarshal(bytes.TrimSpace(body), &env)

	e.Code = env.Code
	switch {
	case env.Message != "":
		e.Message = env.Message
	case env.Msg != "":
		e.Message = env.Msg
	case env.Error != nil && env.Error.Message != "":
		e.Message = env.Error.Message
	}

	switch {
	case status == http.StatusUnauthorized:
		e.Kind = KindTokenExpired
		return e

	case status == http.StatusForbidden:
		switch e.Code {
		case CodeAccountBanned:
			e.Kind = KindAccountBanned
		case CodeQuotaExhausted:
			e.Kind = KindQuotaExhausted
		case CodePayView:
			e.Kind = KindThrottled
		default:
			if env.Action != nil && env.Action.Kind == "pay-view" {
				e.Kind = KindThrottled
				return e
			}
			// 403 tanpa kode bisnis = WAF polos.
			e.Kind = KindWAFBlocked
		}
		return e

	case status == http.StatusBadRequest:
		if isInvalidModelMessage(e.Message) {
			e.Kind = KindInvalidModel
		} else {
			e.Kind = KindBadRequest
		}
		return e

	case status >= 500:
		e.Kind = KindUpstreamError
		return e
	}

	// Status lain: tebak dari kode bisnis bila ada.
	switch e.Code {
	case CodeAccountBanned:
		e.Kind = KindAccountBanned
	case CodeQuotaExhausted:
		e.Kind = KindQuotaExhausted
	case CodePayView:
		e.Kind = KindThrottled
	default:
		e.Kind = KindUnknown
	}
	return e
}

// isInvalidModelMessage mendeteksi pesan "非法模型" (model tidak dikenal).
func isInvalidModelMessage(msg string) bool {
	if msg == "" {
		return false
	}
	return bytes.Contains([]byte(msg), []byte("非法模型")) ||
		bytes.Contains([]byte(msg), []byte("invalid model"))
}

// IsWAFForbiddenBody melaporkan apakah body adalah blok WAF polos
// (bukan response inference yang sah).
func IsWAFForbiddenBody(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	return bytes.Contains(trimmed, []byte(`"message":"forbidden"`)) ||
		bytes.Contains(trimmed, []byte(`"msg":"forbidden"`))
}
