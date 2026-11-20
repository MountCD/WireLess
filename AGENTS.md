# AGENTS.md

WireLess — CLI-конфигуратор WireGuard-шлюза: трафик клиентов `wg0` прозрачно
уходит через sing-box в VLESS/VMess/Trojan/Hysteria2. Сейчас MVP с CLI,
в планах web UI. Пользовательская документация и инструкция по установке —
`README.md` (на русском).

## Команды

```bash
python3 -m wireless.cli --help              # запуск из исходников, install не нужен
python3 -m compileall -q wireless           # синтаксис
python3 -m pytest -q                        # тесты (pip install -e '.[dev]'), без root и сети
pip install -e .                            # на Arch: pip install --break-system-packages -e .
```

Смоук парсеров/генераторов без root и без сети:

```bash
python3 -c "from wireless.parsers.auto import parse_proxy_url as p; from wireless.generators.singbox import generate_singbox_config as g; print(g(p('vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&sni=example.com')))"
```

Готовый конфиг проверяется через `sing-box check -c <file>`.

## Сеть хоста не трогать

`sudo wireless start/stop` — это реальные side effects: `wg-quick up/down wg0`,
mangle-цепочка `WIRELESS_PROXY` с TPROXY, `ip rule fwmark 1 table 100`,
`ip_forward=1`. Не запускать для проверок на dev-машине; генераторы тестируются
напрямую, как выше.

Все команды читают/пишут `/etc/wireless` (root, `0700`), поэтому даже
`add/list/use/remove` на практике требуют root, хотя README показывает их без
`sudo`. Пути захардкожены в `wireless/config.py`; настраивается только
`SINGBOX_BINARY`.

## Как устроено

Поток: URL → `wireless/parsers/*` → dataclass из `wireless/models.py` →
`wireless/generators/{singbox,wireguard}.py` (dict/текст) →
`wireless/services.py` (операции, состояние) → `wireless/managers/*`
(subprocess, PID, iptables) → `wireless/cli.py` (аргументы и вывод).

- Entry point — `wireless = wireless.cli:main`; новые команды добавляются в
  `wireless/cli.py` и вызывают методы `GatewayService` из
  `wireless/services.py`.
- Состояние: `/etc/wireless/configs.json` (список конфигов), `state.json`
  (`active`, `running`, `server_ip`), `subscriptions.json` (пока не
  используется, задел под подписки). В сохранённом dict есть `_type`, потому что
  поле `type` перезаписывается в `__post_init__`; незнакомые ключи при загрузке
  отбрасываются. Служебные ключи `_url`/`_source` тоже отбрасываются.
- Запись состояния — только через `wireless/store.py` (`Store`): атомарная
  замена файла + `flock`, права `0600`, каталоги `0700`. Не писать JSON напрямую.
- Новый протокол: dataclass → парсер → `parsers/auto._PARSERS` →
  `generators/singbox._OUTBOUND_BUILDERS` → `services._PROXY_TYPES`.
- `wireless/cli.py` — только click-аргументы и форматирование; вся логика в
  `parsers/generators/managers/services`. Исключения: `ValueError` (парсинг),
  `NotFoundError`/`ConflictError`/`ServiceError` (операции), `RuntimeError`
  (окружение).
- `PKGBUILD` перечисляет файлы вручную (`source`, `prepare`, `check`), списки
  `py_compile` дублируются в `install.sh` и `install-arch.sh` — новый `.py`
  добавляйте во все места (путь CLI теперь `wireless/cli.py`).

## Web UI

- `wireless/web/` — FastAPI-приложение; зависимости опциональны
  (`pip install 'wireless[web]'`), поэтому импорт `wireless.web.app` ленивый:
  `wireless --help` работает без fastapi.
- `wireless web [--host 127.0.0.1] [--port 8787] [--set-password] [--no-auth]`.
  Не-loopback bind без пароля запрещён (`web/bind.py`).
- `web/auth.py` — stdlib: scrypt-хэш пароля и HMAC-подпись cookie в
  `/etc/wireless/web.json` (`0600`), лимитер логина в памяти. Шаблоны и статика
  в `web/templates`/`web/static`; CSP запрещает inline-скрипты и стили.
- Страницы рендерятся Jinja2, данные тянет `web/static/app.js` через
  `/api/status`. Мутации требуют заголовок `X-CSRF-Token` (значение из
  `<meta name="csrf-token">`) и same-origin `Origin`.
- API: `GET /api/status`, `GET|POST|DELETE /api/proxies`,
  `POST /api/proxies/parse|activate`, `POST /api/gateway/{start|stop|restart}`.
  Наружу отдаётся `services.public_config` — секреты замаскированы, `_url`
  и `_source` вырезаны. Ошибки маппятся в 400/404/409/500 обработчиками
  исключений в `web/app.py`.
- Имя конфига может содержать `/`, поэтому удаление и активация передают его
  query-параметром/в теле, а не в пути.
- Параллельные операции шлюза сериализуются `GatewayService._operation()`:
  лок неблокирующий, второй запрос получает `ConflictError` → 409.

## Грабли

- TPROXY-правила заданы дважды: PostUp/PostDown в `generators/wireguard.py` и
  `managers/routing.py`. Менять синхронно.
- `SINGBOX_BINARY` ищется так: env → `PATH` (`shutil.which`) →
  `whereis -b sing-box` → `/usr/local/bin`, `/usr/bin`, `~/go/bin`.
  Arch-пакет ставит в `/usr/bin/sing-box`.
- Генератор требует sing-box **>= 1.12**: новый DNS (`servers[].type/server`),
  `hijack-dns` вместо `dns-out`, без legacy-полей inbound (`sniff` удалён в 1.13).
  Для старых версий конфиг не подходит.
- У DNS-сервера `local` нельзя ставить `detour: "direct"`: sing-box 1.12+
  отклоняет detour на пустой direct outbound. Без `detour` сервер сам dial'ит
  напрямую. `sing-box check` это **не** ловит — проверяйте `sing-box run`.
- `block` outbound оставлен как `TODO(удалить/переосмыслить)`; DNS-блок
  оставлен только TODO-комментарием — rcode-сервера в новом формате нет.
- `--server-ip` без значения — это локальный адрес интерфейса (UDP-connect к
  8.8.8.8), а не публичный IP за NAT. Для клиентских конфигов передавайте явно.
- `WG_CLIENT_ADDRESS` по умолчанию `10.100.0.2/32` для каждого клиента → второй
  peer конфликтует по адресу; адрес нужно назначать вручную.
- `install*.sh` проверяют `wireless --help` после установки, но не ставят
  `wireless.service` (это делает только PKGBUILD), хотя README обещает
  `systemctl` после `install-arch.sh`.
- `PKGBUILD` настроен на локальные файлы (`makepkg -e`), а `.SRCINFO` — на
  tarball и при этом лежит в `.gitignore`.

## Стиль

- Python ≥3.10, dataclasses, type hints; docstrings по-английски, CLI-тексты и
  README — по-русски, эмодзи в выводе CLI — норма.
- `ValueError` — ошибки парсинга URL, `RuntimeError` — проблемы окружения
  (нет `wg`/`sing-box`, команда не выполнилась); CLI печатает их в stderr и
  делает `sys.exit(1)`.
- Меняя команды или пути, обновляйте `README.md`.
