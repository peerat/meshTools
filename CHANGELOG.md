# Changelog

## EN

### Unreleased

- No changes yet.

### 0.3.2

Added
- Encrypted at-rest storage for profile data (`history.log`, `state.json`, `incoming.json`) using AES-GCM (per-profile key in `keyRings/storage.key`).
- Internal modules `meshtalk/protocol.py` and `meshtalk/storage.py` (plus docs) to separate protocol + storage concerns.
- Apache-2.0 licensing files (`LICENSE`, `NOTICE`) + SPDX headers in Python files.

Changed
- Key exchange waits for confirmation: retries until peer confirmation (`KR2`) or encrypted traffic is observed; logs `KEYOK` on confirmed handshake.
- Text compression selection is automatic; Settings no longer exposes compression choice. Added wire-level aliases `NLTK`/`SPACY`/`TENSORFLOW` mapped to built-in codecs.
- Discovery broadcast and `runtime.log` are enabled by default; `.gitignore` updated to keep local artifacts (tests, zips, runtime data) out of git.

Removed
- Compression preference controls from Settings.

### 0.3.1

Added
- Key-frame receive policy helper with dedicated tests for unicast/broadcast validation paths.
- Extra tests for invalid key length and case-insensitive peer id matching.

Changed
- Key exchange now rejects frames without `fromId` and frames where `fromId` does not match payload peer id.
- Peer id comparison in key-frame validation is now case-insensitive.
- Public key is validated (`32` bytes, X25519 parse) before writing to keyring.
- Documentation synchronized with implementation: compression modes `0..5`, `DICT_ID=2`, discovery send/reply toggles.

### 0.3.0

Added
- Optional message-payload compression block (`MC`) with CRC8 validation.
- Two compression modes: `BYTE_DICT` and `FIXED_BITS`.
- Peer capability marker (`mc=1`) and per-peer compression enable flow.
- New delivery status model for outgoing/incoming single-part and multipart messages.
- Dynamic elapsed timer refresh for pending delivery/receive states.
- Runtime log file (`runtime.log`) with compression marker on send/recv lines.
- Safer history/incoming parsing and multipart receive resume after restart.

Changed
- Compression is applied before encryption and only when size gain reaches `min_gain_bytes`.
- Status text is rebuilt from metadata on language switch.
- Pending state highlight uses orange status/meta text only.
- Group send is marked as sent only if at least one recipient is actually queued.
- First-run discovery defaults are enabled when config is missing.

Removed
- Legacy status wording with `avg/ср`.
- Old legal-policy wording from docs and settings UI (replaced by project vision text).

### 0.2.2 alfa

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

### 0.2.1 alfa

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

- Пока без изменений.

### 0.3.2

Добавлено
- Шифрование данных профиля на диске (`history.log`, `state.json`, `incoming.json`) через AES-GCM (ключ профиля: `keyRings/storage.key`).
- Внутренние модули `meshtalk/protocol.py` и `meshtalk/storage.py` (и документация) для разделения protocol + storage логики.
- Лицензирование Apache-2.0 (`LICENSE`, `NOTICE`) + SPDX‑заголовки в Python‑файлах.

Изменено
- Обмен ключами теперь ждет подтверждения: повторы до `KR2` или появления зашифрованного трафика; в логе появляется `KEYOK` при подтвержденном обмене.
- Выбор сжатия текста полностью автоматический; настройки выбора алгоритма убраны. Добавлены wire-level алиасы `NLTK`/`SPACY`/`TENSORFLOW` поверх встроенных кодеков.
- Discovery broadcast и `runtime.log` включены по умолчанию; `.gitignore` обновлен, чтобы локальные артефакты (tests, zip, runtime data) не попадали в git.

Удалено
- Элементы настроек приоритета сжатия из окна Settings.

### 0.3.1

Добавлено
- Вынесена отдельная политика приема key-frame с отдельными тестами для unicast/broadcast веток.
- Добавлены тесты на невалидную длину ключа и case-insensitive сравнение id peer.

Изменено
- В key exchange отклоняются кадры без `fromId` и кадры, где `fromId` не совпадает с peer id из payload.
- Сравнение id в проверке key-frame теперь регистронезависимое.
- Публичный ключ валидируется (`32` байта, X25519 parse) до записи в keyring.
- Документация синхронизирована с реализацией: режимы сжатия `0..5`, `DICT_ID=2`, раздельные галки discovery send/reply.

### 0.3.0

Добавлено
- Опциональное сжатие payload сообщений блоком `MC` с проверкой CRC8.
- Два режима сжатия: `BYTE_DICT` и `FIXED_BITS`.
- Маркер возможностей peer (`mc=1`) и включение сжатия по peer.
- Новая модель статусов доставки для исходящих/входящих однопакетных и multipart сообщений.
- Динамическое обновление таймера для состояний "в процессе".
- Полный runtime-лог (`runtime.log`) с пометкой метода сжатия в send/recv.
- Более строгий разбор history/incoming и возобновление приема multipart после перезапуска.

Изменено
- Сжатие выполняется до шифрования и только при выигрыше не меньше `min_gain_bytes`.
- Статусы пересобираются из метаданных при переключении языка.
- Оранжевый цвет в ожидании применяется только к статусу/времени.
- Group send помечается как отправленный только если реально поставлен в очередь хотя бы одному получателю.
- Discovery по умолчанию включается при первом запуске при отсутствии настроек.

Удалено
- Старые формулировки статусов с `avg/ср`.
- Старые юридические формулировки из документации и окна настроек (заменены на текст о назначении проекта).

### 0.2.2 alfa

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

### 0.2.1 alfa

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
