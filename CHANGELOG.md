# Changelog

## EN

### Unreleased

Added
- (none)

Changed
- (none)

### 0.3.3 (2026-02-10)

Added
- Settings: `parallel_sends` (packets per `rate_seconds` window) to allow short send bursts without waiting for ACK between packets.
- Settings: `auto_pacing` (adaptive) to auto-tune `rate_seconds`/`parallel_sends` from recent ACK stats.
- Settings: key rotation policy (`security_key_rotation_policy`) with AUTO/STRICT/ALWAYS and explicit TOFU key-mismatch handling.
- Session rekey (ephemeral X25519) inside the encrypted channel (`session_rekey`, enabled by default) to refresh per-peer session keys with low additional control traffic.
- Contact context action: traceroute (Meshtastic `TRACEROUTE_APP`) and post output into dialog.
- Settings: Compression tab with AUTO/OFF/FORCE policy and reversible normalization options.
- Tools: build/normalize SentencePiece vocab for reversible normalization (`tools/build_sp_vocab_from_logs.py`, `tools/normalize_sp_vocab.py`).

Changed
- Traceroute uses retry/backoff policy similar to outgoing sends and shows attempts/hops in message status.
- Traceroute output resolves node names from Meshtastic node DB as `LongName [Short] !id` and is refreshed periodically.
- Traceroute and key-exchange events now include detailed diagnostics in runtime log (initiator/reason, retries, timeouts); crypto log lines are highlighted.
- Contact list: lock icon is shown only for confirmed two-way key exchange and expires after 24 hours; key age/last-seen annotations refined.
- Settings: log toggles moved to Log tab; Apply now updates retry/limits/rate/parallel immediately (no restart needed); new event type colorization (`PACE`, `HEALTH`, `DISCOVERY`, `RADIO`, `GUI`, `QUEUE`).
- Compression: added `mc_zstd` mode id and reversible normalizations ("token stream", "SentencePiece vocab") before binary codecs.
- Dependencies: `zstandard` is now included in `requirements.txt` (no separate optional requirements file).
- Runtime log: added compression telemetry lines (`COMPRESS` per message and periodic `COMPSTAT` totals with gain/mode/normalization).
- Settings UI: tab title contrast improved for Windows themes.

### 0.3.2 (2026-02-10)

Added
- At-rest storage sealing for profile data (`history.log`, `state.json`, `incoming.json`) using AES-GCM (per-profile key in `keyRings/storage.key`).
- Internal modules `meshtalk/protocol.py` and `meshtalk/storage.py` (plus docs) to separate protocol + storage concerns.
- Apache-2.0 licensing files (`LICENSE`, `NOTICE`) + SPDX headers in Python files.

Changed
- Key exchange waits for confirmation: retries until peer confirmation (`KR2`) or verified payload is observed; logs `KEYOK` on confirmed handshake.
- Text compression selection is automatic; Settings no longer exposes compression choice.
- Discovery broadcast and `runtime.log` are enabled by default; `.gitignore` updated to keep local artifacts (tests, zips, runtime data) out of git.

Removed
- Compression preference controls from Settings.

### 0.3.1 (2026-02-08)

Added
- Key-frame receive policy helper with dedicated tests for unicast/broadcast validation paths.
- Extra tests for invalid key length and case-insensitive peer id matching.

Changed
- Key exchange now rejects frames without `fromId` and frames where `fromId` does not match payload peer id.
- Peer id comparison in key-frame validation is now case-insensitive.
- Public key is validated (`32` bytes, X25519 parse) before writing to keyring.
- Documentation synchronized with implementation: compression modes `0..5`, `DICT_ID=2`, discovery send/reply toggles.

### 0.3.0 (2026-02-08)

Added
- Optional message-payload compression block (`MC`) with CRC8 validation.
- Two compression modes: `BYTE_DICT` and `FIXED_BITS`.
- Peer capability marker (`mc=1`) and per-peer compression enable flow.
- New delivery status model for outgoing/incoming single-part and multipart messages.
- Dynamic elapsed timer refresh for pending delivery/receive states.
- Runtime log file (`runtime.log`) with compression marker on send/recv lines.
- Safer history/incoming parsing and multipart receive resume after restart.

Changed
- Compression is applied before MT-WIRE sealing and only when size gain reaches `min_gain_bytes`.
- Status text is rebuilt from metadata on language switch.
- Pending state highlight uses orange status/meta text only.
- Group send is marked as sent only if at least one recipient is actually queued.
- First-run discovery defaults are enabled when config is missing.

Removed
- Legacy status wording with `avg/ср`.
- Old legal-policy wording from docs and settings UI (replaced by project vision text).

### 0.2.2 alfa (2026-02-06)

Added
- Exponential retry backoff with jitter.
- Per-peer queue limit and explicit fail statuses (`timeout`, `queue_limit`, `too_long`, `payload_too_big`).
- Health summary log line (`peers`, `tracked`, `pending`, `avg_rtt`).
- Settings switch for writing `runtime.log`.
- Unit tests for status formatting and runtime-state snapshot concurrency.

Changed
- Message list layout spacing, margins, timestamp anchor, unread dot position.
- Message body text kept neutral; state color remains on status/time area.
- Incoming complete timestamp persisted as `received_at_ts` for stable rendering.
- Settings save path works even when radio is disconnected.

Removed
- Duplicate history records from repeated reload paths.

### 0.2.1 alfa (2026-02-06)

Added
- GUI startup without radio with auto-reconnect and waiting state.
- Top header with `Client ID`, names, masked `pub`, ID copy, and key-regen triple click.
- Unified settings log view with copy button.
- Discovery broadcast workflow with startup burst and idle schedule.
- Per-node profile storage (`<node_id>/config.json`, `state.json`, `history.log`, `incoming.json`, `keyRings/`).
- Multipart message progress and resume support.

Changed
- Contact/message spacing and bubble/timestamp placement.
- Key refresh flow with jitter and decrypt-failure auto-request.
- Settings persistence across restarts.

Removed
- Duplicate "attempt" lines from chat history view after restart.

## RU

### Unreleased

Добавлено
- (нет)

Изменено
- (нет)

### 0.3.3 (2026-02-10)

Добавлено
- Настройки: `parallel_sends` (сколько пакетов можно отправить подряд в одном окне `rate_seconds`) для быстрых отправок без ожидания ACK между пакетами.
- Настройки: `auto_pacing` (адаптивно) автоподбирает `rate_seconds`/`parallel_sends` по статистике ACK.
- Настройки: политика смены ключа (`security_key_rotation_policy`) с AUTO/STRICT/ALWAYS и явной обработкой TOFU key-mismatch.
- Rekey сессии (ephemeral X25519) внутри зашифрованного канала (`session_rekey`, по умолчанию включено) для периодического обновления session key с небольшим служебным трафиком.
- Действие в контекстном меню контакта: traceroute (Meshtastic `TRACEROUTE_APP`) и вывод результата в диалог.
- Настройки: вкладка Сжатие с политикой AUTO/OFF/FORCE и вариантами обратимой нормализации.
- Инструменты: сборка/нормализация SentencePiece vocab для обратимой нормализации (`tools/build_sp_vocab_from_logs.py`, `tools/normalize_sp_vocab.py`).

Изменено
- Traceroute использует политику повторов/backoff как исходящие отправки и показывает attempts/hops в статусе.
- Вывод traceroute сопоставляет имена узлов из базы Meshtastic как `LongName [Short] !id` и база периодически обновляется.
- Traceroute и key exchange пишут подробную диагностику в runtime‑лог (инициатор/причина, повторы, таймауты); строки криптографии подсвечены.
- Список контактов: замок показывается только при подтвержденном двустороннем обмене и имеет срок валидности 24 часа; уточнены подписи “ключ/в сети”.
- Settings: настройки лога перенесены на вкладку Log; Apply теперь применяет повтор/лимиты/rate/параллельно сразу (без перезапуска); добавлена цветовая разметка типов событий (`PACE`, `HEALTH`, `DISCOVERY`, `RADIO`, `GUI`, `QUEUE`).
- Сжатие: добавлен режим `mc_zstd` и обратимые нормализации ("token stream", "SentencePiece vocab") перед бинарными кодеками.
- Зависимости: `zstandard` включен в `requirements.txt` (без отдельного optional-файла зависимостей).
- Runtime-лог: добавлены телеметрические строки по сжатию (`COMPRESS` на сообщение и периодический `COMPSTAT` с суммарным выигрышем/режимом/нормализацией).
- UI настроек: повышен контраст заголовков вкладок для тем Windows.

### 0.3.2 (2026-02-10)

Добавлено
- Запечатывание данных профиля на диске (`history.log`, `state.json`, `incoming.json`) через AES-GCM (ключ профиля: `keyRings/storage.key`).
- Внутренние модули `meshtalk/protocol.py` и `meshtalk/storage.py` (и документация) для разделения protocol + storage логики.
- Лицензирование Apache-2.0 (`LICENSE`, `NOTICE`) + SPDX‑заголовки в Python‑файлах.

Изменено
- Обмен ключами теперь ждет подтверждения: повторы до `KR2` или появления валидированного payload; в логе появляется `KEYOK` при подтвержденном обмене.
- Выбор сжатия текста полностью автоматический; настройки выбора алгоритма убраны.
- Discovery broadcast и `runtime.log` включены по умолчанию; `.gitignore` обновлен, чтобы локальные артефакты (tests, zip, runtime data) не попадали в git.

Удалено
- Элементы настроек приоритета сжатия из окна Settings.

### 0.3.1 (2026-02-08)

Добавлено
- Вынесена отдельная политика приема key-frame с отдельными тестами для unicast/broadcast веток.
- Добавлены тесты на невалидную длину ключа и case-insensitive сравнение id peer.

Изменено
- В key exchange отклоняются кадры без `fromId` и кадры, где `fromId` не совпадает с peer id из payload.
- Сравнение id в проверке key-frame теперь регистронезависимое.
- Публичный ключ валидируется (`32` байта, X25519 parse) до записи в keyring.
- Документация синхронизирована с реализацией: режимы сжатия `0..5`, `DICT_ID=2`, раздельные галки discovery send/reply.

### 0.3.0 (2026-02-08)

Добавлено
- Опциональное сжатие payload сообщений блоком `MC` с проверкой CRC8.
- Два режима сжатия: `BYTE_DICT` и `FIXED_BITS`.
- Маркер возможностей peer (`mc=1`) и включение сжатия по peer.
- Новая модель статусов доставки для исходящих/входящих однопакетных и multipart сообщений.
- Динамическое обновление таймера для состояний "в процессе".
- Полный runtime-лог (`runtime.log`) с пометкой метода сжатия в send/recv.
- Более строгий разбор history/incoming и возобновление приема multipart после перезапуска.

Изменено
- Сжатие выполняется до запечатывания MT-WIRE и только при выигрыше не меньше `min_gain_bytes`.
- Статусы пересобираются из метаданных при переключении языка.
- Оранжевый цвет в ожидании применяется только к статусу/времени.
- Group send помечается как отправленный только если реально поставлен в очередь хотя бы одному получателю.
- Discovery по умолчанию включается при первом запуске при отсутствии настроек.

Удалено
- Старые формулировки статусов с `avg/ср`.
- Старые юридические формулировки из документации и окна настроек (заменены на текст о назначении проекта).

### 0.2.2 alfa (2026-02-06)

Добавлено
- Экспоненциальный retry backoff с jitter.
- Лимит очереди на peer и явные fail-статусы (`timeout`, `queue_limit`, `too_long`, `payload_too_big`).
- Периодическая health-строка в логе (`peers`, `tracked`, `pending`, `avg_rtt`).
- Галка в Settings для включения/выключения `runtime.log`.
- Unit-тесты для форматирования статусов и конкурентного snapshot runtime-состояния.

Изменено
- Отступы/интервалы списка сообщений, привязка временной метки, позиция индикатора непрочитанных.
- Текст сообщения оставлен нейтральным; цвет состояния только у зоны статуса/времени.
- Для завершенных входящих сохраняется `received_at_ts` для стабильного отображения.
- Сохранение настроек работает и при отключенном радио.

Удалено
- Дубли записей истории при повторной загрузке.

### 0.2.1 alfa (2026-02-06)

Добавлено
- Запуск GUI без радио с авто‑переподключением и состоянием ожидания.
- Верхняя строка с `Client ID`, именами, маской `pub`, копированием ID и тройным кликом для регенерации ключей.
- Единое окно лога в настройках с кнопкой копирования.
- Discovery broadcast со стартовым burst и idle-режимом.
- Хранение данных по профилям нод (`<node_id>/config.json`, `state.json`, `history.log`, `incoming.json`, `keyRings/`).
- Прогресс multipart и возобновление приема.

Изменено
- Компоновка контактов/сообщений и позиционирование временной метки.
- Автообновление ключей (jitter + автозапрос при decrypt-fail).
- Сохранение настроек между перезапусками.

Удалено
- Повторы "attempt" в истории чата после перезапуска.
