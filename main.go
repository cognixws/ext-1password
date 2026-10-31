// Command picode-1password is the 1Password secret-source process for
// COGNIX[WS] (ADR-0388, door L of ADR-0109). The daemon starts it while the
// extension is on; it answers one resolve call over loopback and publishes
// the names of the items it can see. A value exists in memory between the
// vendor's answer and the resolve response, and nowhere else: nothing is
// written, cached to disk, logged or sent to the host.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

const resolvePath = "/picode/vault/resolve"

// Error classes the daemon understands (ADR-0388): revoked refuses the
// launch; the others are diagnostics and the turn falls to request_key.
const (
	errRevoked     = "revoked"
	errForbidden   = "forbidden"
	errMissing     = "missing"
	errUnavailable = "unavailable"
)

// resolveError is a classified answer: HTTP status carries the class and the
// body one clipped line of the vendor's own words.
type resolveError struct {
	class  string
	detail string
}

func (e *resolveError) Error() string { return e.class + ": " + e.detail }

func (e *resolveError) status() int {
	switch e.class {
	case errRevoked:
		return http.StatusConflict
	case errForbidden:
		return http.StatusForbidden
	case errMissing:
		return http.StatusNotFound
	default:
		return http.StatusServiceUnavailable
	}
}

// vendor is the one seam over the 1Password SDK: what a test fakes.
type vendor interface {
	// item answers one field's value.
	item(ctx context.Context, vaultTitle, itemTitle, field string) (string, error)
	// items answers the metadata the tab may show (label, vault), never values.
	items(ctx context.Context) ([]sourceItem, error)
}

type sourceItem struct {
	Ref   string `json:"ref"`
	Label string `json:"label"`
	Vault string `json:"vault"`
}

func main() {
	log.SetFlags(0)
	port := os.Getenv("PICODE_EXT_PORT")
	secret := os.Getenv("PICODE_EXT_PROXY_SECRET")
	hostURL := strings.TrimRight(os.Getenv("PICODE_URL"), "/")
	token := os.Getenv("PICODE_EXT_TOKEN")
	extID := os.Getenv("PICODE_EXT_ID")
	if port == "" || secret == "" {
		log.Fatal("this process runs supervised by COGNIX[WS]; start it from the extension, not by hand")
	}

	var v vendor
	fake := os.Getenv("EXT_1PASSWORD_FAKE")
	if fake != "" {
		if os.Getenv("EXT_QA_MODE") != "1" {
			log.Fatal("the fixture resolver answers fake values and runs only with EXT_QA_MODE=1")
		}
		var err error
		v, err = newFakeVendor(fake)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("QA fixture resolver on %s", fake)
	} else {
		v = &onepasswordVendor{host: host{url: hostURL, token: token, extID: extID}, mu: &sync.Mutex{}}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+resolvePath, func(w http.ResponseWriter, r *http.Request) {
		// The daemon's proxy secret: the only caller this endpoint accepts.
		if r.Header.Get("X-PiCode-Proxy-Secret") != secret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var in struct {
			Ref string `json:"ref"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil || in.Ref == "" {
			answer(w, &resolveError{class: errMissing, detail: "the resolve call carried no reference"})
			return
		}
		parts, err := parseRef(in.Ref)
		if err != nil {
			answer(w, &resolveError{class: errMissing, detail: clip(err.Error())})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		value, err := v.item(ctx, parts.vault, parts.item, parts.field)
		if err != nil {
			answer(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
	})
	mux.HandleFunc("GET /picode/vault/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PiCode-Proxy-Secret") != secret {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	// The names the tab may show, republished when the token changes.
	if pub, ok := v.(publisher); ok && hostURL != "" && token != "" {
		go pub.publishLoop(host{url: hostURL, token: token})
	}

	log.Printf("1Password source listening on 127.0.0.1:%s", port)
	if err := http.ListenAndServe("127.0.0.1:"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func answer(w http.ResponseWriter, err error) {
	re, ok := err.(*resolveError)
	if !ok {
		re = &resolveError{class: errUnavailable, detail: clip(err.Error())}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(re.status())
	_ = json.NewEncoder(w).Encode(map[string]string{"class": re.class, "detail": re.detail})
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// refParts is one op:// reference. The vault and item may be titles or IDs;
// the field may be a label, an ID, or the word "password" for the built-in
// password field.
type refParts struct {
	vault, item, field string
}

var errBadRef = errors.New("a reference reads op://<vault>/<item>/<field>")

func parseRef(ref string) (refParts, error) {
	rest, ok := strings.CutPrefix(ref, "op://")
	if !ok {
		return refParts{}, errBadRef
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return refParts{}, errBadRef
	}
	if len(parts) > 4 {
		return refParts{}, errBadRef
	}
	field := parts[2]
	if len(parts) == 4 {
		// op://vault/item/section/field: the field is the last part; the
		// section only narrows the search, and this resolver matches the
		// field label within the whole item.
		field = parts[3]
		if field == "" {
			return refParts{}, errBadRef
		}
	}
	return refParts{vault: parts[0], item: parts[1], field: field}, nil
}

// publisher is a vendor that can refresh the tab's item names.
type publisher interface {
	publishLoop(h host)
}

// publishItems hands the host the names only, through the publish door.
func publishItems(h host, items []sourceItem) {
	if len(items) > 500 {
		items = items[:500]
	}
	body, _ := json.Marshal(map[string]any{"items": items})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url+"/api/ext/v1/vaults/items", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("X-PiCode-Extension-Token", h.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("publish: %v", err)
		return
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Printf("publish: %d", res.StatusCode)
		return
	}
	log.Printf("published %d item names", len(items))
}

type host struct {
	url, token, extID string
}

// publishLoop runs at most every 30 seconds: read the token from the
// settings the host keeps sealed, and when it changed, list what the
// service account can see and publish names only.
func (o *onepasswordVendor) publishLoop(h host) {
	seen := ""
	for {
		token := o.settingToken(h)
		if token != "" && token != seen {
			if err := o.connect(token); err != nil {
				log.Printf("connect: %v", err)
			} else {
				seen = token
				items, err := o.items(context.Background())
				if err != nil {
					log.Printf("publish: %v", err)
					continue
				}
				publishItems(h, items)
			}
		}
		time.Sleep(30 * time.Second)
	}
}

// settingToken reads its one secret setting back from the host. The value
// stays in this process's memory.
func (o *onepasswordVendor) settingToken(h host) string {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.url+"/api/ext/v1/settings", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-PiCode-Extension-Token", h.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		Settings map[string]any `json:"settings"`
	}
	if json.NewDecoder(res.Body).Decode(&out) != nil {
		return ""
	}
	t, _ := out.Settings["service_account_token"].(string)
	return t
}

// onepasswordVendor is the real vendor behind the official SDK.
type onepasswordVendor struct {
	host host
	mu   *sync.Mutex
	// client and the metadata caches live behind mu. The caches hold names
	// and ids only; a value is fetched per resolve and never stored.
	client          *onepassword.Client
	vaultIDsByTitle map[string]string            // title -> id
	vaultTitles     map[string]string            // id -> title
	itemIDs         map[string]map[string]string // vault id -> item title -> id
	cacheAt         time.Time
	fakeItems       []sourceItem
}

func (o *onepasswordVendor) connect(token string) error {
	if !strings.HasPrefix(token, "ops_") {
		return &resolveError{class: errRevoked, detail: "the saved value is not a 1Password service account token"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("COGNIX[WS]", "0.1.0"),
	)
	if err != nil {
		return &resolveError{class: errRevoked, detail: clip(err.Error())}
	}
	o.mu.Lock()
	o.client = client
	o.cacheAt = time.Time{}
	o.mu.Unlock()
	log.Printf("connected to 1Password")
	return nil
}

// ensureCache refreshes the vault and item name caches at most once a
// minute. Names only.
func (o *onepasswordVendor) ensureCache(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.client == nil {
		return &resolveError{class: errForbidden, detail: "no service account token is set; connect on the extension's page"}
	}
	if time.Since(o.cacheAt) < time.Minute && o.vaultIDsByTitle != nil {
		return nil
	}
	vaults, err := o.client.Vaults().List(ctx)
	if err != nil {
		return classifySDK(err)
	}
	o.vaultIDsByTitle, o.vaultTitles, o.itemIDs = map[string]string{}, map[string]string{}, map[string]map[string]string{}
	for _, v := range vaults {
		o.vaultIDsByTitle[strings.ToLower(v.Title)] = v.ID
		o.vaultTitles[v.ID] = v.Title
		overviews, err := o.client.Items().List(ctx, v.ID)
		if err != nil {
			continue
		}
		byTitle := map[string]string{}
		for _, it := range overviews {
			byTitle[strings.ToLower(it.Title)] = it.ID
		}
		o.itemIDs[v.ID] = byTitle
	}
	o.cacheAt = time.Now()
	return nil
}

func (o *onepasswordVendor) item(ctx context.Context, vaultTitle, itemTitle, field string) (string, error) {
	if err := o.ensureCache(ctx); err != nil {
		return "", err
	}
	o.mu.Lock()
	vaultID := o.vaultIDsByTitle[strings.ToLower(vaultTitle)]
	if vaultID == "" {
		vaultID = vaultTitle // an ID was named directly
	}
	vaultName := o.vaultTitles[vaultID]
	byTitle := o.itemIDs[vaultID]
	itemID := byTitle[strings.ToLower(itemTitle)]
	o.mu.Unlock()
	if itemID == "" {
		return "", &resolveError{class: errMissing, detail: fmt.Sprintf("there is no item %q in vault %q", itemTitle, vaultName)}
	}
	it, err := o.client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return "", classifySDK(err)
	}
	for _, f := range it.Fields {
		if strings.EqualFold(f.Title, field) || f.ID == field || (strings.EqualFold(field, "password") && f.FieldType == onepassword.ItemFieldTypeConcealed) {
			if f.Value == "" {
				return "", &resolveError{class: errMissing, detail: fmt.Sprintf("the field %q is empty", field)}
			}
			return f.Value, nil
		}
	}
	return "", &resolveError{class: errMissing, detail: fmt.Sprintf("the item %q has no field %q", itemTitle, field)}
}

func (o *onepasswordVendor) items(ctx context.Context) ([]sourceItem, error) {
	if err := o.ensureCache(ctx); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	out := []sourceItem{}
	for vaultID, byTitle := range o.itemIDs {
		vaultName := o.vaultTitles[vaultID]
		for title := range byTitle {
			out = append(out, sourceItem{Ref: fmt.Sprintf("op://%s/%s/password", vaultName, title), Label: title, Vault: vaultName})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

func classifySDK(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "401"), strings.Contains(strings.ToLower(msg), "unauthorized"), strings.Contains(strings.ToLower(msg), "invalid token"):
		return &resolveError{class: errRevoked, detail: "the service account token was refused; connect again"}
	case strings.Contains(msg, "403"), strings.Contains(strings.ToLower(msg), "access denied"), strings.Contains(strings.ToLower(msg), "not authorized"):
		return &resolveError{class: errForbidden, detail: "the service account cannot reach this vault or item"}
	case strings.Contains(msg, "404"), strings.Contains(strings.ToLower(msg), "not found"):
		return &resolveError{class: errMissing, detail: "the vault or item is not there (or is not shared)"}
	default:
		return &resolveError{class: errUnavailable, detail: clip(msg)}
	}
}

// fakeVendor answers from a JSON fixture: {"refs": {"op://…": "value"}, "items":
// [{"ref","label","vault"}]}. QA only: main refuses to start it without
// EXT_QA_MODE=1, and the binary built for release carries the same refusal.
type fakeVendor struct {
	refs     map[string]string
	itemList []sourceItem
}

func newFakeVendor(path string) (vendor, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f struct {
		Refs  map[string]string `json:"refs"`
		Items []sourceItem      `json:"items"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return &fakeVendor{refs: f.Refs, itemList: f.Items}, nil
}

func (f *fakeVendor) item(_ context.Context, vault, item, field string) (string, error) {
	v, ok := f.refs[fmt.Sprintf("op://%s/%s/%s", vault, item, field)]
	if !ok {
		return "", &resolveError{class: errMissing, detail: fmt.Sprintf("the fixture has no %s/%s/%s", vault, item, field)}
	}
	return v, nil
}

func (f *fakeVendor) items(_ context.Context) ([]sourceItem, error) { return f.itemList, nil }

// publishLoop publishes the fixture's names once, then keeps the 30s rhythm
// of the real vendor, so the QA tab behaves like production.
func (f *fakeVendor) publishLoop(h host) {
	for {
		publishItems(h, f.itemList)
		time.Sleep(30 * time.Second)
	}
}

var _ = io.Discard
