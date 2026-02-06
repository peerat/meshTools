# Changelog

## 0.2.2 alfa
- UI: message bubbles aligned with fixed margins and gaps; timestamp offset refined.
- UI: unread indicator dot position adjusted.
- Logs: timestamps added to unprefixed log lines; self-id logged on connect.
- Radio: auto-reconnect, screen cleared on disconnect, per-node config reload.
- Storage: per-node queue reset on node switch; incoming multipart resume.
- Fixes: history dedupe on reload; removed double recv logging; send/discovery error handling.

## 0.2.1 alfa
- GUI: auto‑start even without radio, with retry and status in top bar.
- GUI: top bar shows `Client ID` + names + masked pub key; click copies Client ID.
- GUI: triple‑click on `pub:` regenerates keys and broadcasts new key.
- UI: improved message layout, timestamps, and contact spacing.
- Logging: unified debug log in Settings (colored) + Copy log button.
- Discovery: optional broadcast discovery (send/allow) with burst on start and idle schedule.
- Keys: auto refresh with jitter; auto re‑request on decrypt failures.
- Messages: multi‑packet support with progress `pK/N`, avg attempts/hops.
- History: de‑duplication on load and cleaner logging.
- Build: Windows exe in windowed mode; reduced PySide6 modules.
- Fix: settings discovery flags saving and Qt6 click deprecation.
- Fix: top bar refresh after key regeneration.
- Fix: settings persist across restarts (runtime options, discovery, UI).
- Docs: MIT license and author info added.
- Data: per‑node storage for config/history/state/keys (<node_id>/ рядом с приложением).
- Data: settings/history loaded only after node initialization.
- UI: unread indicator (orange dot) in contact list.
- Fix: history reload shows only sent/received (no duplicate attempts).
- Fix: multipart receive resumes after restart.
