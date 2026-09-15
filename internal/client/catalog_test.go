package client

import "testing"

func TestRouteIDMapsCatalog(t *testing.T) {
	want := map[string]string{
		"auto":              "zai_auto",
		"auto-fast":         "zai_auto-fast",
		"glm-5.3":           "zaicoding_glm-5.3",
		"glm-5.3-flash":     "zai_glm-5.3-flash",
		"deepseek-v4-pro":   "tdpsk_deepseek-v4-pro-202606",
		"deepseek-v4-flash": "tdpsk_deepseek-v4-flash-202605",
	}
	for model, route := range want {
		if got := RouteID(model); got != route {
			t.Errorf("RouteID(%q) = %q, want %q", model, got, route)
		}
	}
}

// glm-5.3 adalah model yang diminta user: pastikan mapping-nya tidak pernah
// bergeser ke prefix "zai_" (yang tidak ada di upstream).
func TestRouteIDGLM53UsesCodingPrefix(t *testing.T) {
	if got := RouteID("glm-5.3"); got != "zaicoding_glm-5.3" {
		t.Fatalf("RouteID(glm-5.3) = %q, want zaicoding_glm-5.3", got)
	}
}

func TestRouteIDPassesThroughRawRouteID(t *testing.T) {
	if got := RouteID("zaicoding_glm-5.3"); got != "zaicoding_glm-5.3" {
		t.Errorf("route id mentah harus diteruskan apa adanya, dapat %q", got)
	}
}

func TestSupportedModelsExcludesUnverifiedGLMTurbo(t *testing.T) {
	models := SupportedModels()
	for _, m := range models {
		if m == "glm-5-turbo" {
			t.Fatal("glm-5-turbo tidak ada di upstream (400 非法模型) dan tidak boleh dipublikasikan")
		}
	}
	if len(models) != 6 {
		t.Fatalf("jumlah model = %d, want 6 (%v)", len(models), models)
	}
}

func TestKnownModel(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"glm-5.3", true},
		{"zaicoding_glm-5.3", true},
		{"glm-5-turbo", false},
		{"zai_glm-5-turbo", false},
		{"glm-5.2", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := KnownModel(tt.in); got != tt.want {
			t.Errorf("KnownModel(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestCatalogIsACopy(t *testing.T) {
	c := Catalog()
	c[0].ID = "mutated"
	if Catalog()[0].ID == "mutated" {
		t.Fatal("Catalog() harus mengembalikan salinan, bukan referensi ke slice internal")
	}
}

func TestBodyModel(t *testing.T) {
	tests := map[string]string{
		"zaicoding_glm-5.3": "glm-5.3",
		"zai_auto":          "auto",
		"zai_auto-fast":     "auto-fast",
	}
	for route, want := range tests {
		if got := BodyModel(route); got != want {
			t.Errorf("BodyModel(%q) = %q, want %q", route, got, want)
		}
	}
}
