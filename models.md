# Модели данных WireLess

Карта всех структур, которые WireLess читает и пишет. Источник истины —
код: `wireless/models.py` (dataclass'ы), `wireless/store.py` (файлы),
`wireless/services.py` (сериализация). При изменении полей обновляйте и этот
файл.

---

## 1. ProxyConfig и подклассы

Базовый dataclass (`wireless/models.py`):

| Поле | Тип | По умолчанию | Комментарий |
|---|---|---|---|
| `type` | `str` | — | Перезаписывается в `__post_init__` подкласса |
| `server` | `str` | — | Хост прокси-сервера |
| `port` | `int` | — | Порт |
| `name` | `str` | `""` | Имя конфига; если пустое — `{type}_{server}_{port}` |
| `uuid` | `str` | `""` | VLESS/VMess |
| `password` | `str` | `""` | Trojan |

### VlessConfig (`type = "vless"`)

| Поле | Тип | По умолчанию |
|---|---|---|
| `flow` | `str` | `""` (`xtls-rprx-vision`) |
| `security` | `str` | `"none"` (`none` / `tls` / `reality`) |
| `sni` | `str` | `""` |
| `fp` | `str` | `""` (uTLS fingerprint) |
| `pbk` | `str` | `""` (Reality public key) |
| `sid` | `str` | `""` (Reality short id) |
| `path` | `str` | `""` (WS path / gRPC service name) |
| `host` | `str` | `""` (WS Host header) |
| `network` | `str` | `"tcp"` (`tcp` / `ws` / `grpc`) |
| `encryption` | `str` | `"none"` |

### VmessConfig (`type = "vmess"`)

| Поле | Тип | По умолчанию |
|---|---|---|
| `alter_id` | `int` | `0` |
| `cipher` | `str` | `"auto"` |
| `network` | `str` | `"tcp"` (`tcp` / `ws` / `grpc` / `h2`) |
| `path` | `str` | `""` |
| `host` | `str` | `""` |
| `tls` | `bool` | `False` |
| `sni` | `str` | `""` |

### TrojanConfig (`type = "trojan"`)

| Поле | Тип | По умолчанию |
|---|---|---|
| `sni` | `str` | `""` |
| `path` | `str` | `""` |
| `host` | `str` | `""` |
| `security` | `str` | `"tls"` |
| `network` | `str` | `"tcp"` (`tcp` / `ws`) |

### Hysteria2Config (`type = "hysteria2"`)

| Поле | Тип | По умолчанию |
|---|---|---|
| `auth` | `str` | `""` |
| `obfs` | `str` | `""` (`salamander` или пусто) |
| `obfs_password` | `str` | `""` |
| `sni` | `str` | `""` |
| `insecure` | `bool` | `False` |

> `type` — вычисляемое поле: `__post_init__` каждого подкласса перезаписывает
> его, поэтому при сериализации отдельно сохраняется `_type` (см. ниже).

### WireGuard

`WireGuardServerConfig`: `interface`, `private_key`, `public_key`, `address`,
`listen_port`, `dns` (`1.1.1.1`), `peers` (список клиентов).

`WireGuardClientConfig`: `private_key`, `public_key`, `server_public_key`,
`server_endpoint` (`host:port`), `allowed_ips` (`0.0.0.0/0, ::/0`),
`address` (`10.100.0.2/32`), `dns` (`1.1.1.1`), `persistent_keepalive` (`25`).

---

## 2. `/etc/wireless/configs.json`

Список сохранённых прокси. Каждый элемент — `dataclasses.asdict()` плюс
служебные ключи:

```json
[
  {
    "_type": "vless",
    "type": "vless",
    "server": "example.com",
    "port": 443,
    "name": "MyReality",
    "uuid": "11111111-1111-1111-1111-111111111111",
    "password": "",
    "flow": "xtls-rprx-vision",
    "security": "reality",
    "sni": "www.microsoft.com",
    "fp": "chrome",
    "pbk": "PUBLIC_KEY",
    "sid": "SHORT_ID",
    "path": "",
    "host": "",
    "network": "tcp",
    "encryption": "none",
    "_url": "vless://1111...@example.com:443?security=reality#MyReality"
  }
]
```

Правила:

- `_type` — обязателен для восстановления класса (`dict_to_proxy_config`).
- `_url` — исходный URL; нужен для редактирования и будущих подписок.
  **Не является полем dataclass** и отбрасывается при загрузке.
- `_source` (зарезервировано под подписки) — `{kind, id, remote_key}`,
  также отбрасывается при восстановлении.
- Незнакомые ключи игнорируются: `dict_to_proxy_config` передаёт только поля
  dataclass'а. Это позволяет добавлять служебные поля без миграций.
- `name` — основной ключ; `_name` поддерживается для чтения старых файлов.
- Дубликаты имён запрещены (`ConflictError` при `add`).

## 3. `/etc/wireless/state.json`

```json
{
  "active": "MyReality",
  "running": true,
  "server_ip": "1.2.3.4"
}
```

| Ключ | Тип | Смысл |
|---|---|---|
| `active` | `str` | Имя активного конфига; отсутствует, если не выбран |
| `running` | `bool` | Флаг последнего успешного `start`/`stop` |
| `server_ip` | `str` | IP, записанный в клиентские конфиги |

`running` — это **намерение**, а не факт: реальное состояние читается из
процессов (`wg show`, PID-файл sing-box, iptables).

## 4. `/etc/wireless/web.json`

Создаётся web UI при первом запуске, права `0600`:

```json
{
  "password_hash": "scrypt$16384$8$1$<salt_b64>$<hash_b64>",
  "secret": "<64 hex-символа>"
}
```

- `password_hash` — scrypt (`n=16384, r=8, p=1, dklen=32`), соль на пароль.
- `secret` — HMAC-SHA256 ключ для подписи cookie сессии.
- Открытый пароль не хранится; при первом запуске генерируется и печатается
  один раз.

## 5. `/etc/wireless/subscriptions.json` (зарезервировано)

Файл создаётся store'ом, но пока не используется. Планируемая схема:

```json
[
  {
    "id": "sub_7f3a91c2",
    "name": "My provider",
    "url": "https://provider/sub/TOKEN",
    "enabled": true,
    "user_agent": "WireLess/0.1",
    "interval": 86400,
    "etag": "\"a1b2\"",
    "last_modified": "Wed, 12 Nov 2026 09:00:00 GMT",
    "fingerprint": "sha256:9c1e...",
    "last_fetch_at": 1763550000,
    "last_success_at": 1763550000,
    "last_error": "",
    "last_status": "ok",
    "http_status": 200,
    "usage": {"upload": 0, "download": 0, "total": 0, "expire": 0},
    "config_count": 12
  }
]
```

## 6. `/etc/wireless/wireguard/`

| Файл | Права | Содержимое |
|---|---|---|
| `server_keys.json` | `0600` | `{"private": "...", "public": "..."}` |
| `clients.json` | `0600` | список `WireGuardClientConfig` |
| `wg0.conf` | `0600` | сгенерированный конфиг интерфейса |

## 7. `/etc/wireless/singbox/`

| Файл | Содержимое |
|---|---|
| `config.json` | результат `generate_singbox_config()` |
| `singbox.pid` | PID процесса sing-box |
| `singbox.log` | stdout/stderr sing-box |

---

## 8. Формат API web UI

Публичное представление конфига (`services.public_config`): поля dataclass'а
плюс `_type`; секреты (`uuid`, `password`, `auth`, `obfs_password`)
маскируются как `••••`, `_url` и `_source` не отдаются.

| Метод | Путь | Тело / ответ |
|---|---|---|
| `GET` | `/api/status` | снимок состояния (см. ниже) |
| `GET` | `/api/proxies` | `{"active": "…", "configs": [...]}` |
| `POST` | `/api/proxies` | `{"url": "...", "name": "..."}` → конфиг |
| `POST` | `/api/proxies/parse` | `{"url": "..."}` → предпросмотр без сохранения |
| `DELETE` | `/api/proxies/{name}` | `{"ok": true}` |
| `POST` | `/api/proxies/{name}/activate` | `{"active": "..."}` |
| `POST` | `/api/gateway/{start\|stop\|restart}` | `{"server_ip": "..."}` → снимок |

`GET /api/status`:

```json
{
  "active": "MyReality",
  "server_ip": "1.2.3.4",
  "running": true,
  "configs_count": 3,
  "wireguard": {"interface": "wg0", "running": true, "details": "..."},
  "singbox": {"running": true, "pid": 1234, "binary": "/usr/bin/sing-box",
              "config": "/etc/wireless/singbox/config.json",
              "log": "/etc/wireless/singbox/singbox.log"},
  "routing": true
}
```

Ошибки: `400` — парсинг/валидация, `401` — нет сессии, `403` — CSRF/чужой
`Origin`, `404` — нет конфига, `409` — дубликат имени или параллельная
операция шлюза, `429` — лимит логина, `500` — сбой окружения.
