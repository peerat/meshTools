# Changelog

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
