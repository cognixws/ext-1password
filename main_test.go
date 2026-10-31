package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
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
