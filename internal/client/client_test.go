package client

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeProxy(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "host port", in: "127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{name: "host port credentials", in: "127.0.0.1:8080:user:pass", want: "http://user:pass@127.0.0.1:8080"},
		{name: "url", in: "http://user:pass@127.0.0.1:8080", want: "http://user:pass@127.0.0.1:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeProxy(tt.in)
			if err != nil {
				t.Fatalf("NormalizeProxy() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeProxy() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientUsesConfiguredProxy(t *testing.T) {
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits++
		if !strings.HasPrefix(r.URL.String(), "http://") {
			t.Errorf("proxy received URL %q, want absolute URL", r.URL.String())
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "proxied")
	}))
	defer proxy.Close()

	c := New("", "")
	if err := c.SetProxy(proxy.URL); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://upstream.invalid/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "proxied" {
		t.Fatalf("response = %q, want proxied", body)
	}
	if proxyHits != 1 {
		t.Fatalf("proxy hits = %d, want 1", proxyHits)
	}
}
