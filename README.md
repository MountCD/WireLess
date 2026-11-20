# WireLess — WireGuard Gateway for Proxy Protocols

WireLess превращает любой сервер в **WireGuard VPN** шлюз, который прозрачно
туннелирует весь трафик через прокси-сервер (VLESS, VMess, Trojan, Hysteria2).

```
Клиент (WireGuard)  ──▶  wg0  ──▶  iptables TPROXY  ──▶  sing-box  ──▶  Прокси-сервер  ──▶  Интернет
```

---

## Архитектура

```
┌────────────────────────────────────────────────────────────┐
│                      Сервер WireLess                        │
│                                                            │
│  WireGuard (wg0:51820)                                     │
│       │                                                    │
│       ▼                                                    │
│  iptables TPROXY (mangle → WIRELESS_PROXY)                 │
│       │                                                    │
│       ▼                                                    │
│  sing-box tproxy inbound (:2082)                           │
│       │           │                                        │
│       │           ├─ socks5 inbound (:2080)                │
│       │           └─ http  inbound (:2081)                 │
│       │                                                    │
│       ▼                                                    │
│  sing-box outbound (vless/vmess/trojan/hysteria2)          │
│       │                                                    │
│       ▼                                                    │
│  Прокси-сервер в интернете                                 │
└────────────────────────────────────────────────────────────┘
```

**Поддерживаемые протоколы:**
| Протокол    | Транспорт          | TLS/Security       |
|-------------|--------------------|--------------------|
| VLESS       | TCP, WebSocket, gRPC | Reality, TLS, None |
| VMess       | TCP, WebSocket, H2 | TLS                |
| Trojan      | TCP, WebSocket     | TLS                |
| Hysteria2   | UDP (QUIC)         | TLS + obfs         |

---

## Установка

### Требования
- Linux (Ubuntu 20.04+ / Debian 11+)
- root / sudo доступ
- Открытый порт UDP `51820` в firewall
- sing-box **>= 1.12** (генератор использует новый формат DNS и rule actions)

### Быстрая установка

```bash
git clone https://github.com/yourname/wireless
cd wireless
sudo ./install.sh
```

Скрипт автоматически:
1. Устанавливает `wireguard-tools`, `iptables`, `iproute2`
2. Скачивает последний релиз `sing-box` с GitHub
3. Устанавливает Python-зависимости
4. Создаёт директории `/etc/wireless/`
5. Регистрирует команду `wireless` в PATH

### Arch Linux

```bash
# Вариант 1: install-arch.sh (локально)
sudo ./install-arch.sh

# Вариант 2: через AUR (после публикации)
yay -S wireless
# или
paru -S wireless
```

`install-arch.sh` автоматически определяет наличие AUR-хелпера (yay/paru/aura)
и устанавливает `sing-box-bin` из AUR. При отсутствии хелпера — скачивает
бинарник напрямую с GitHub. Python-пакеты ставятся с `--break-system-packages`
(правило Arch для externally-managed Python).

### Ручная установка (Debian/Ubuntu)

```bash
# Системные пакеты
sudo apt install wireguard-tools iptables iproute2 python3-pip

# sing-box (пример для amd64; нужна версия >= 1.12)
curl -sSfL https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-linux-amd64.tar.gz \
  | tar -xz --strip-components=1 -C /usr/local/bin/ sing-box-1.14.4-linux-amd64/sing-box

# Python
pip3 install -r requirements.txt
pip3 install -e .
```

### Ручная установка (Arch Linux)

```bash
# Системные пакеты
sudo pacman -S wireguard-tools iptables iproute2 python python-pip

# sing-box из AUR
yay -S sing-box-bin

# Python
pip install --break-system-packages -r requirements.txt
pip install --break-system-packages -e .
```

### systemd (Arch / systemd-based)

```bash
# После установки через PKGBUILD / install-arch.sh:
sudo systemctl enable --now wireless
sudo systemctl status wireless
```

---

## Использование

### 1. Добавить прокси конфиг

```bash
# VLESS + Reality
wireless add "vless://a1b2c3d4-...@example.com:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBLIC_KEY&sid=SHORT_ID&flow=xtls-rprx-vision&type=tcp#MyReality"

# VLESS + TLS + WebSocket
wireless add "vless://uuid@host:443?security=tls&sni=host&type=ws&path=/ws&host=host#MyWS"

# VMess
wireless add "vmess://BASE64_JSON_HERE"

# Trojan
wireless add "trojan://password@host:443?sni=host.example.com#MyTrojan"

# Hysteria2
wireless add "hysteria2://auth_token@host:443?obfs=salamander&obfs-password=PASS&sni=host#MyHy2"
```

### 2. Просмотр и выбор конфига

```bash
wireless list        # показать все сохранённые конфиги
wireless use 0       # активировать по индексу
wireless use MyReality  # активировать по имени
```

### 3. Запустить сервер

```bash
# Автоматически определяет публичный IP
sudo wireless start

# Или указать IP явно
sudo wireless start --server-ip 1.2.3.4
```

### 4. Получить конфиг для клиента

```bash
wireless client           # вывести конфиг в консоль
wireless client --qr      # показать QR-код (сканировать мобильным клиентом)
wireless client --save ~/wg-client.conf   # сохранить в файл
```

### 5. Статус

```bash
wireless status
```

```
Active config: MyReality
Server IP:     1.2.3.4

🟢 WireGuard (wg0): running
🟢 sing-box: running (pid=12345)
🟢 iptables TPROXY routing: active

Proxy configs saved: 3
```

### 6. Остановить

```bash
sudo wireless stop
```

### 7. Перезапустить

```bash
sudo wireless restart              # сохраняет последний server IP
sudo wireless restart --server-ip 1.2.3.4
```

### 8. Удалить конфиг

```bash
wireless remove MyReality
```

---

## WireGuard Клиенты

Подключайтесь стандартным WireGuard клиентом:

| Платформа | Клиент |
|-----------|--------|
| iOS       | [App Store](https://apps.apple.com/app/wireguard/id1441195209) |
| Android   | [Google Play](https://play.google.com/store/apps/details?id=com.wireguard.android) |
| macOS     | [App Store](https://apps.apple.com/app/wireguard/id1451685025) |
| Windows   | [wireguard.com](https://www.wireguard.com/install/) |
| Linux     | `apt install wireguard-tools` |

После получения конфига (`wireless client`):
- **QR-код** — сканируйте в мобильном приложении
- **Файл** — импортируйте через "Import tunnel from file"
- **Вручную** — скопируйте конфиг в интерфейс клиента

---

## Файловая структура

```
/etc/wireless/
├── singbox/
│   ├── config.json      # текущий sing-box конфиг
│   ├── singbox.pid      # PID процесса sing-box
│   └── singbox.log      # логи sing-box
├── wireguard/
│   ├── wg0.conf         # конфиг WireGuard интерфейса
│   ├── server_keys.json # серверные ключи (600)
│   └── clients.json     # список клиентских ключей
├── state.json           # состояние (активный конфиг, running флаг)
└── configs.json         # сохранённые прокси конфиги
```

---

## Схема трафика

```
[Телефон/ноутбук]
      │
      │  WireGuard VPN (UDP 51820)
      ▼
[Сервер wg0: 10.100.0.1]
      │
      │  iptables TPROXY (mangle table)
      │  Обходит: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
      ▼
[sing-box tproxy :2082]
      │
      │  Outbound: VLESS/VMess/Trojan/Hysteria2
      ▼
[Прокси-сервер в интернете]
      │
      ▼
[Интернет 🌍]
```

---

## Безопасность

- Серверные ключи WireGuard хранятся в `/etc/wireless/wireguard/server_keys.json` с правами `600`
- Конфиг WireGuard (`wg0.conf`) имеет права `600`
- Директория `/etc/wireless/wireguard/` имеет права `700`
- sing-box конфиг хранится в `/etc/wireless/singbox/config.json`

---

## Troubleshooting

**sing-box не запускается:**
```bash
cat /etc/wireless/singbox/singbox.log

# Проверьте версию sing-box (нужна >= 1.12):
sing-box version

# Проверьте сгенерированный конфиг:
sing-box check -c /etc/wireless/singbox/config.json
```

**WireGuard не поднимается:**
```bash
# Проверьте загружен ли модуль ядра:
lsmod | grep wireguard
modprobe wireguard
```

**TPROXY не работает:**
```bash
# Убедитесь что модуль xt_TPROXY загружен:
modprobe xt_TPROXY
# Проверьте правила:
iptables -t mangle -L -n -v
ip rule show
ip route show table 100
```

**Трафик не проходит:**
```bash
# Проверьте IP forwarding:
cat /proc/sys/net/ipv4/ip_forward   # должен быть 1

# Проверьте статус всех компонентов:
wireless status
```

---

## Лицензия

MIT
