# CSP DSB
A Chrome browser extension that lets you modify or remove Content-Security-Policy headers on any website. Edit directives or use no-csp to disable CSP entirely.

---

## Why Install?

- **Debug CSP breakage** — quickly test which directive is blocking resources on your site
- **Relax strict CSP** — temporarily loosen policies on trusted internal tools or dev environments
- **Remove CSP entirely** — type `no-csp` to strip all CSP headers from a site
- **No coding required** — everything is configured through a clean popup UI

---

## Key Features

### Per-Site Rules
Each rule targets a specific URL pattern (e.g. `https://example.com/*`). The current site's CSP is auto-detected when adding a new rule.

### Structured Directive Editor
Edit individual directives (script-src, style-src, connect-src, etc.) in a visual UI — no need to memorize CSP syntax. Add, remove, or modify directives with simple input fields.

### Raw CSP Mode
Switch to raw text mode for full manual control over the policy string. Advanced users can write any valid CSP policy directly.

### `no-csp` — Remove All CSP
Switch to raw mode and type only `no-csp` to completely remove all Content-Security-Policy headers from the target site.

### Master Toggle
Enable or disable all rules globally with one click. The switch remembers its last state across browser restarts.

### Export & Import
Back up your rule set to a JSON file or share rules across devices.

---

## How to Use

1. Install the extension from the Chrome Web Store
2. Click the **CSP DSB** icon in your browser toolbar
2. Click **"+ Add Rule"** — the current site's URL and CSP are auto-filled
3. Edit directives in the structured view, or click **"Edit raw CSP"** for manual input
4. Click **"Replace & Apply"**
5. Refresh the target page to see the changes take effect

---

## Example Use Cases

| Scenario | Setup |
|---|---|
| Block inline scripts on your own site for testing | Add rule for your domain → set `script-src 'self'` |
| Allow WebSocket connections to localhost | Add rule → add `connect-src` → set `ws://localhost:8080` |
| Disable CSP completely on a dev server | Add rule → switch to raw mode → type `no-csp` |
| Fix a site broken by too-strict CSP | Auto-detect the site's CSP → remove the blocking directive |

---

## Source Code

This extension is open source. View the code, report issues, or contribute at:

**[github.com/etMing/csp-dsb](https://github.com/etMing/csp-dsb)**
