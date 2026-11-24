package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	ok := map[string]refParts{
		"op://Dev/API keys/Stripe":            {vault: "Dev", item: "API keys", field: "Stripe"},
		"op://Dev/API keys/Stripe/Password":   {vault: "Dev", item: "API keys", field: "Password"},
		"op://Team/Web/GitHub token/section1": {vault: "Team", item: "Web", field: "section1"},
	}
	for ref, want := range ok {
		got, err := parseRef(ref)
		if err != nil || got != want {
			t.Fatalf("%s: got %+v err=%v", ref, got, err)
		}
	}
	for _, ref := range []string{"", "op://", "op://Dev", "op://Dev/API keys", "op://Dev//Stripe", "op://a/b/c/d/e", "https://x/y/z", "op://Dev/API keys/"} {
		if _, err := parseRef(ref); err == nil {
			t.Fatalf("%q should not parse", ref)
		}
	}
}

type staticVendor struct {
	value    string
	err      error
	itemList []sourceItem
}

func (s *staticVendor) item(_ context.Context, _, _, _ string) (string, error) {
	return s.value, s.err
}

func (s *staticVendor) items(_ context.Context) ([]sourceItem, error) {
	return s.itemList, nil
}

// serve spins the process's mux around a vendor, as main does.
func serve(t *testing.T, v vendor, secret string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+resolvePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PiCode-Proxy-Secret") != secret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var in struct {
			Ref string `json:"ref"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Ref == "" {
			answer(w, &resolveError{class: errMissing, detail: "the resolve call carried no reference"})
			return
		}
		parts, err := parseRef(in.Ref)
		if err != nil {
			answer(w, &resolveError{class: errMissing, detail: clip(err.Error())})
			return
		}
		value, err := v.item(context.Background(), parts.vault, parts.item, parts.field)
		if err != nil {
			answer(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestResolveContract(t *testing.T) {
	secret := strings.Repeat("s", 32)
	ts := serve(t, &staticVendor{value: "sk-live-9"}, secret)

	// The happy row: the daemon's shape in, one value out — and nothing
	// else on the body.
	res, err := http.NewRequest("POST", ts.URL+resolvePath, strings.NewReader(`{"ref":"op://Dev/API keys/Stripe"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Header.Set("X-PiCode-Proxy-Secret", secret)
	got, err := http.DefaultClient.Do(res)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(got.Body).Decode(&out)
	if len(out) != 1 || out["value"] != "sk-live-9" {
		t.Fatalf("value: %#v", out)
	}

	// A wrong secret is 403 before anything else.
	req, err := http.NewRequest("POST", ts.URL+resolvePath, strings.NewReader(`{"ref":"op://a/b/c"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-PiCode-Proxy-Secret", "wrong")
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong secret: %d", res2.StatusCode)
	}
}

func TestResolveClassesMapToStatuses(t *testing.T) {
	secret := "k"
	cases := map[string]struct {
		err    error
		status int
		class  string
	}{
		"revoked":     {&resolveError{class: errRevoked, detail: "token refused"}, http.StatusConflict, errRevoked},
		"forbidden":   {&resolveError{class: errForbidden, detail: "not shared"}, http.StatusForbidden, errForbidden},
		"missing":     {&resolveError{class: errMissing, detail: "no item"}, http.StatusNotFound, errMissing},
		"unavailable": {&resolveError{class: errUnavailable}, http.StatusServiceUnavailable, errUnavailable},
		"plain":       {errors.New("boom"), http.StatusServiceUnavailable, errUnavailable},
	}
	for name, tc := range cases {
		ts := serve(t, &staticVendor{err: tc.err}, secret)
		req, _ := http.NewRequest("POST", ts.URL+resolvePath, strings.NewReader(`{"ref":"op://a/b/c"}`))
		req.Header.Set("X-PiCode-Proxy-Secret", secret)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Class string `json:"class"`
		}
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if res.StatusCode != tc.status || out.Class != tc.class {
			t.Fatalf("%s: %d %q", name, res.StatusCode, out.Class)
		}
	}
}

func TestErrorBodiesCarryOnlyClassAndDetail(t *testing.T) {
	secret := "k"
	ts := serve(t, &staticVendor{err: &resolveError{class: errForbidden, detail: "the service account cannot reach this vault"}}, secret)
	req, _ := http.NewRequest("POST", ts.URL+resolvePath, strings.NewReader(`{"ref":"op://a/b/c"}`))
	req.Header.Set("X-PiCode-Proxy-Secret", secret)
	got, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(got.Body).Decode(&out)
	if len(out) != 2 || out["class"] != errForbidden {
		t.Fatalf("error body: %#v", out)
	}
}

func TestFakeVendorFixture(t *testing.T) {
	path := t.TempDir() + "/fixture.json"
	fixture := `{"refs": {"op://Dev/API keys/Stripe": "sk-test"}, "items": [{"ref": "op://Dev/API keys/password", "label": "API keys", "vault": "Dev"}]}`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := newFakeVendor(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.item(context.Background(), "Dev", "API keys", "Stripe")
	if err != nil || got != "sk-test" {
		t.Fatalf("fake resolve: %q %v", got, err)
	}
	items, err := v.items(context.Background())
	if err != nil || len(items) != 1 || items[0].Label != "API keys" {
		t.Fatalf("fake items: %#v %v", items, err)
	}
}

func TestFakeModeRefusedWithoutQA(t *testing.T) {
	// The refusal lives in main(); here the gate's two facts are pinned: the
	// env name and the guard value.
	if os.Getenv("EXT_QA_MODE") == "1" {
		t.Skip("the runner itself runs with QA on")
	}
	if os.Getenv("EXT_1PASSWORD_FAKE") != "" {
		t.Fatal("EXT_1PASSWORD_FAKE must not be set outside QA")
	}
}

// TestSettingTokenTrustsTheHostCA reproduces the handshake failure the host
// logged every 30s ("remote error: tls: bad certificate"): the settings read
// went out on a client that does not trust the daemon's own authority. The
// host client built from PICODE_CA_FILE verifies and reads the sealed token.
func TestSettingTokenTrustsTheHostCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ext/v1/settings" || r.Header.Get("X-PiCode-Extension-Token") != "ext-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"values":{},"secrets":{"service_account_token":"ops_abc"},"retired":{}}`))
	}))
	defer srv.Close()
	h := host{url: srv.URL, token: "ext-token"}

	caFile := filepath.Join(t.TempDir(), "root.pem")
	der := srv.Certificate().Raw
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := settingToken(http.DefaultClient, h); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a client without the host CA must fail the handshake, got %v", err)
	}
	got, err := settingToken(hostClientFor(caFile), h)
	if err != nil || got != "ops_abc" {
		t.Fatalf("host client: got %q, %v; want ops_abc", got, err)
	}
	if got, err := settingToken(hostClientFor(caFile), host{url: srv.URL, token: "wrong"}); err == nil || got != "" {
		t.Fatalf("a refused read must be an error with no token, got %q, %v", got, err)
	}
}

func TestHostClientForFallsBackToSystemRoots(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string]string{"unset": "", "missing": filepath.Join(t.TempDir(), "none.pem"), "junk": junk} {
		c := hostClientFor(file)
		if c == http.DefaultClient || c.Timeout == 0 {
			t.Fatalf("%s: want a system-roots client with a timeout, got %+v", name, c)
		}
	}
}

// tlsHost serves handler over TLS and returns the host and a client that
// trusts it through a CA file, the way the supervisor hands one over.
func tlsHost(t *testing.T, handler http.HandlerFunc) (host, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return host{url: srv.URL, token: "ext-token"}, hostClientFor(caFile)
}

func TestSettingTokenIgnoresTypedValues(t *testing.T) {
	h, c := tlsHost(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"values":{"poll":30,"verbose":true},"secrets":{"service_account_token":"ops_abc"},"retired":{}}`))
	})
	if got, err := settingToken(c, h); err != nil || got != "ops_abc" {
		t.Fatalf("got %q, %v; want ops_abc", got, err)
	}
}

func TestSettingTokenSaysUnreadableSecrets(t *testing.T) {
	h, c := tlsHost(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"values":{},"secrets":{},"retired":{},"secretsUnreadable":true,"problem":"enter them again"}`))
	})
	got, err := settingToken(c, h)
	if err == nil || got != "" || !strings.Contains(err.Error(), "enter them again") {
		t.Fatalf("got %q, %v; want an error carrying the host's problem", got, err)
	}
}

func TestPublishItemsTrustsTheHostCA(t *testing.T) {
	var got struct{ Items []sourceItem }
	h, c := tlsHost(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ext/v1/vaults/items" || r.Header.Get("X-PiCode-Extension-Token") != "ext-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
	})
	items := []sourceItem{{Ref: "op://Dev/Stripe/key", Label: "Stripe", Vault: "Dev"}}
	if err := publishItems(http.DefaultClient, h, items); err == nil {
		t.Fatal("a client without the host CA must fail")
	}
	if err := publishItems(c, h, items); err != nil || len(got.Items) != 1 || got.Items[0].Label != "Stripe" {
		t.Fatalf("publish: %v, host got %+v", err, got)
	}
}

// A failed listing is not "published": the loop must try again next round.
func TestPublishOnceReportsEachFailure(t *testing.T) {
	h, c := tlsHost(t, func(w http.ResponseWriter, _ *http.Request) {})
	if err := publishOnce(c, h, func() ([]sourceItem, error) { return nil, errors.New("1Password is down") }); err == nil {
		t.Fatal("a failed listing must be an error")
	}
	if err := publishOnce(http.DefaultClient, h, func() ([]sourceItem, error) { return nil, nil }); err == nil {
		t.Fatal("a failed publish must be an error")
	}
	if err := publishOnce(c, h, func() ([]sourceItem, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
}
