package client

import "testing"

// Endpoint /userapi/v1/user-profile menjawab HTTP 200 walau akun diblokir,
// jadi status harus dibaca dari kode bisnis di body — bukan dari status HTTP.
func TestProfileStatusBanned(t *testing.T) {
	tests := []struct {
		name string
		in   *ProfileStatus
		want bool
	}{
		{"410004 user banned", &ProfileStatus{Code: 410004, Msg: "User banned"}, true},
		{"sukses", &ProfileStatus{Code: 0, Msg: "SUCCESS"}, false},
		{"kode lain", &ProfileStatus{Code: 400000, Msg: "User not logged in"}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.Banned(); got != tt.want {
				t.Fatalf("Banned() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserProfileRejectsEmptyToken(t *testing.T) {
	c := New("", "")
	if _, err := c.UserProfile(t.Context(), ""); err == nil {
		t.Fatal("token kosong harus error")
	}
}
