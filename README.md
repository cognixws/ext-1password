# 1Password secret source for COGNIX[WS]

An extension (door L of ADR-0109, ADR-0388): it registers COGNIX[WS]'s
generic Vaults tab as a 1Password source. The daemon resolves one binding
at launch by asking this process over loopback; the value rides the same
0600 file as every key and is never stored, cached, logged or shown.

## Connect

1. In 1Password: Developer → Service accounts → New, scoped to only the
   vaults you want to share.
2. Install this folder as an extension, open its page, and paste the
   `ops_…` token in **Service account token**. The host seals it; this
   process reads it back in memory only.

## Layout

- `picode-extension.json` — the manifest (`vaultSource: true`,
  `vaults:publish`, the secret setting, the supervised process).
- `main.go` — the process: `POST /picode/vault/resolve` (proxy secret,
  10s), the metadata publish through `POST /api/ext/v1/vaults/items`
  (names only, 500 cap), the token read from its sealed setting.
- `qa/package/` — the QA build: resolves from `qa/fixture.json` and only
  starts with `EXT_QA_MODE=1`. Never install it where real work runs.

## Dependencies

- `github.com/1password/onepassword-sdk-go` — the vendor's official SDK;
  service accounts sign every request, and hand-rolling that is worse
  than one justified dependency (ADR-0388's decision line).

## Validated (2026-10-31)

- Unit: reference parsing, error classes → HTTP statuses, the resolve
  contract (secret, one value out), the fixture vendor.
- Standalone binary in QA mode: value with the right secret, 403 with a
  wrong one, 404 + class for an unknown reference.
- Against a real COGNIX[WS] scratch instance: install, enable, the
  supervised process running, the item names published through the
  Host API and visible on the Vaults tab, a binding created from the
  page. Not yet validated live: a real service account token.
