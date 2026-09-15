package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/hirotomasato/autoclawpi/internal/client"
	"github.com/hirotomasato/autoclawpi/internal/config"
)

type loginHandler struct {
	cl          *client.Client
	cfg         *config.Config
	vendor      string
	codeCh      chan string
	verifyCh    chan string
	stateValue  string
	serverPort  int
	navigateURI string
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	vendor := fs.String("vendor", "zai", "oauth: zai | google")
	port := fs.Int("port", 0, "port lokal (0 = pilih dari ALL_PORTS 18432/19654/19723/53699)")
	fs.Parse(args)

	cfg, cl := loadAll()
	loginPort := *port

	// 1) captcha config
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	capCfg, err := cl.CaptchaConfig(ctx)
	if err != nil {
		return fmt.Errorf("captcha config: %w", err)
	}
	fmt.Printf("captcha: supplier=%s enabled=%v scene=%s\n",
		capCfg.Data.Supplier, capCfg.Data.Enabled, capCfg.Data.SceneID)

	// 2) cari port dari ALL_PORTS (harus terdaftar di OAuth client Z.ai)
	allPorts := []int{18432, 19654, 19723, 53699}
	var actualPort int
	var ln net.Listener
	var errPort error
	if loginPort == 0 {
		// coba port-port app asli dulu
		for _, p := range allPorts {
			ln, errPort = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if errPort == nil {
				actualPort = p
				break
			}
		}
		// fallback ke random port kalo semua terpakai (tapi redirect URI rejected)
		if ln == nil {
			ln, errPort = net.Listen("tcp", "127.0.0.1:0")
			if errPort != nil {
				return fmt.Errorf("gak bisa dengerin port: %w", errPort)
			}
			actualPort = ln.Addr().(*net.TCPAddr).Port
			fmt.Println("PERINGATAN: redirect URI mungkin ditolak karena port gak terdaftar")
		}
	} else {
		ln, errPort = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", loginPort))
		if errPort != nil {
			return fmt.Errorf("port %d terpakai: %w", loginPort, errPort)
		}
		actualPort = loginPort
	}
	_ = ln.Close() // nanti start ulang

	h := &loginHandler{
		cl:          cl,
		cfg:         cfg,
		vendor:      *vendor,
		codeCh:      make(chan string, 1),
		verifyCh:    make(chan string, 1),
		serverPort:  actualPort,
		navigateURI: fmt.Sprintf("http://localhost:%d/auth/callback-%s", actualPort, *vendor),
	}

	// 3) start HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleRoot)
	mux.HandleFunc("/captcha-result", h.handleCaptchaResult)
	mux.HandleFunc(fmt.Sprintf("/auth/callback-%s", *vendor), h.handleOAuthCallback)

	srv := &http.Server{Handler: mux}
	ln2, _ := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", actualPort))
	go func() { _ = srv.Serve(ln2) }()
	defer srv.Close()

	// 4) buka browser ke captcha page
	captchaURL := fmt.Sprintf("http://localhost:%d/?scene=%s&prefix=%s&supplier=%s",
		actualPort, capCfg.Data.SceneID, capCfg.Data.Prefix, capCfg.Data.Supplier)
	fmt.Printf("\nbuka di browser: %s\n", captchaURL)
	fmt.Println("solve captcha-nya, nanti lanjut OAuth otomatis.")
	openBrowser(captchaURL)

	// 5) tunggu verifyParam
	var verifyParam string
	select {
	case vp := <-h.verifyCh:
		if vp == "" {
			return fmt.Errorf("captcha gagal atau dibatalkan")
		}
		verifyParam = vp
		fmt.Println("captcha solved! ambil URL OAuth...")
	case <-ctx.Done():
		return fmt.Errorf("timeout menunggu captcha solve")
	}

	// 6) ambil OAuth URL
	oauthURL, oauthState, err := cl.OAuthURL(ctx, *vendor, h.navigateURI, "autoclaw", map[string]any{
		"ali_captcha_verify_param": verifyParam,
	})
	if err != nil {
		return fmt.Errorf("oauth-url: %w", err)
	}
	h.stateValue = oauthState // pake state dari server, bukan generate sendiri
	fmt.Println("buka browser ke:", oauthURL)
	openBrowser(oauthURL)

	// 7) tunggu callback
	select {
	case code := <-h.codeCh:
		if code == "" {
			return fmt.Errorf("callback tanpa code")
		}
		return finishLogin(ctx, cl, *vendor, code, h.stateValue, h.navigateURI)
	case <-ctx.Done():
		return fmt.Errorf("timeout menunggu OAuth callback")
	}
}

func (h *loginHandler) handleRoot(w http.ResponseWriter, r *http.Request) {
	scene := r.URL.Query().Get("scene")
	prefix := r.URL.Query().Get("prefix")
	supplier := r.URL.Query().Get("supplier")

	html := captchaPage(scene, prefix, supplier, h.serverPort)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (h *loginHandler) handleCaptchaResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", 405)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	r.Body.Close()
	var res struct {
		VerifyParam string `json:"verifyParam"`
		Provider    string `json:"provider"`
		RID         string `json:"rid"`
		Pass        bool   `json:"pass"`
	}
	json.Unmarshal(body, &res)
	if res.VerifyParam != "" {
		w.Write([]byte(`{"ok":true,"msg":"captcha diterima, lanjut OAuth..."}`))
		select {
		case h.verifyCh <- res.VerifyParam:
		default:
		}
	} else if res.RID != "" && res.Pass {
		w.Write([]byte(`{"ok":true,"msg":"captcha rid diterima"}`))
		select {
		case h.verifyCh <- res.RID:
		default:
		}
	} else {
		w.Write([]byte(`{"ok":false,"msg":"gagal"}`))
	}
}

func (h *loginHandler) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" {
		http.Error(w, "missing code", 400)
		return
	}
	if state != "" && state != h.stateValue {
		http.Error(w, "state mismatch", 400)
		return
	}
	w.Write([]byte("<html><body><h2>Login berhasil! Kembali ke terminal.</h2></body></html>"))
	select {
	case h.codeCh <- code:
	default:
	}
}

func openBrowser(u string) {
	switch runtime.GOOS {
	case "linux":
		exec.Command("xdg-open", u).Start()
	case "darwin":
		exec.Command("open", u).Start()
	default:
		exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	}
}

// captchaPage menghasilkan halaman HTML captcha Aliyun (SDK v2).
func captchaPage(scene, prefix, supplier string, port int) string {
	_ = supplier
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>autoclawpi - Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#111;color:#eee;display:flex;justify-content:center;align-items:center;min-height:100vh}
.container{text-align:center;max-width:500px;padding:40px}
h1{font-size:24px;margin-bottom:8px;color:#fff}
p{font-size:14px;color:#888;margin-bottom:24px}
#captcha-zone{min-height:100px;margin:20px 0}
#captcha-btn{display:inline-block;padding:12px 32px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer;transition:background .2s}
#captcha-btn:hover{background:#1d4ed8}
#captcha-btn:disabled{opacity:.5;cursor:not-allowed}
.status{font-size:13px;color:#666;margin-top:16px}
.status.done{color:#4caf50}
.status.error{color:#f44336}
.loading{color:#888;font-size:14px;margin:10px}
</style>
</head>
<body>
<div class="container">
<h1>autoclawpi</h1>
<p>Klik tombol di bawah untuk verifikasi captcha, lalu login ke Z.ai</p>
<div id="captcha-zone"></div>
<button id="captcha-btn" disabled>Memuat...</button>
<div id="status" class="status"></div>
</div>

<script>
window.AliyunCaptchaConfig = {
  region: "ga",
  prefix: %q
};
</script>
<script src="https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"></script>
<script>
var scene = %q;
var statusEl = document.getElementById('status');
var btn = document.getElementById('captcha-btn');

// Init sekali pas SDK ready
function initCaptcha() {
  if (typeof initAliyunCaptcha !== 'function') {
    statusEl.textContent = 'Memuat SDK captcha...';
    statusEl.className = 'status';
    setTimeout(initCaptcha, 500);
    return;
  }
  statusEl.textContent = 'Captcha siap. Klik tombol.';
  statusEl.className = 'status';
  btn.textContent = 'Mulai Verifikasi';
  btn.disabled = false;

  initAliyunCaptcha({
    SceneId: scene,
    mode: "popup",
    element: "#captcha-zone",
    button: "#captcha-btn",
    captchaVerifyCallback: function(captchaVerifyParam) {
      statusEl.textContent = 'Captcha solved! Mengirim...';
      statusEl.className = 'status done';
      document.getElementById('captcha-zone').innerHTML = '<div style="color:#4caf50;font-size:18px;padding:20px">✓ Captcha terselesaikan</div>';
      btn.style.display = 'none';
      fetch('/captcha-result', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({verifyParam: captchaVerifyParam, provider: 'aliyun'})
      }).then(function(r){return r.json()}).then(function(d){
        if(d.ok) {
          statusEl.textContent = d.msg;
          statusEl.className = 'status done';
        } else {
          statusEl.textContent = 'Error: ' + d.msg;
          statusEl.className = 'status error';
          btn.disabled = false;
          btn.style.display = 'inline-block';
        }
      });
      return { captchaResult: true, bizResult: true };
    },
    onBizResultCallback: function(bizResult) {},
    slideStyle: { width: 360, height: 40 },
    language: "en",
    onError: function(error) {
      statusEl.textContent = 'Error: ' + (error.message || JSON.stringify(error));
      statusEl.className = 'status error';
      btn.disabled = false;
    }
  });
}

if (document.readyState === 'complete') {
  setTimeout(initCaptcha, 300);
} else {
  window.addEventListener('load', function(){ setTimeout(initCaptcha, 300); });
}
</script>
</body>
</html>`, prefix, scene)
}
