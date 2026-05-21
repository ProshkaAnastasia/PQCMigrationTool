# GOST Client-Server Demo

Демонстрационное клиент-серверное приложение на C++17, использующее **российские криптографические стандарты ГОСТ** через библиотеку OpenSSL с движком `gost-engine`.

---

## 📋 Используемые стандарты

| Стандарт | Название | Алгоритм (OpenSSL) | Где используется |
|---|---|---|---|
| **ГОСТ 34.10-2018** | Цифровая подпись | `gost2012_256` (EVP_PKEY) | Аутентификация клиента/сервера в протоколе рукопожатия |
| **VKO ГОСТ Р 34.10-2012** | Выработка общего ключа | `EVP_PKEY_derive` + `EVP_PKEY_CTRL_SET_IV` | Выработка сессионного ключа при рукопожатии |
| **ГОСТ 34.12-2018** | Блочные шифры (Кузнечик + Магма) | `kuznyechik-ctr/cbc`, `magma-ctr` | Шифрование сообщений в сессии |
| **ГОСТ 34.13-2018** | Режимы работы блочных шифров | `CTR`, `CBC`, `CFB` | Применяется совместно с ГОСТ 34.12-2018 |
| **ГОСТ 34.11-2018** | Хэш-функция «Стрибог» | `md_gost12_256`, `md_gost12_512` | HMAC, хэш в подписях, хэш для деривации ключей |

---

## 🗂 Структура проекта

```
gost_project/
├── CMakeLists.txt          # Основной CMake-файл
├── README.md               # Документация
├── run_demo.sh             # Скрипт автоматической демонстрации
├── setup_gost_engine.sh    # Скрипт установки gost-engine
├── include/
│   ├── gost_utils.hpp      # ГОСТ-утилиты: интерфейс (подробные комментарии по стандартам)
│   └── protocol.hpp        # Протокол клиент-сервер (структуры сообщений)
└── src/
    ├── gost_utils.cpp      # ГОСТ-утилиты: реализация (карта использования стандартов)
    ├── protocol.cpp        # Сериализация/десериализация протокола
    ├── server.cpp          # TCP-сервер с ГОСТ-криптографией
    ├── client.cpp          # TCP-клиент с ГОСТ-криптографией
    └── gen_certs.cpp       # Генератор ключей + полное тестирование всех алгоритмов
```

---

## 🔧 Зависимости

- **CMake** ≥ 3.16
- **OpenSSL** ≥ 1.1.0 (рекомендуется 3.x)
- **gost-engine** — движок ГОСТ-алгоритмов для OpenSSL
- Компилятор C++17 (GCC ≥ 9 или Clang ≥ 10)

---

## ⚙️ Установка gost-engine

### Debian/Ubuntu

```bash
# Автоматически:
sudo bash setup_gost_engine.sh

# Или вручную:
sudo apt-get install -y libssl-dev cmake g++
git clone https://github.com/gost-engine/engine.git
cd engine && git submodule update --init
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
make -j$(nproc) && sudo make install
```

После установки настройте `/etc/ssl/openssl.cnf`:

```ini
# В самое начало файла (перед первой секцией):
openssl_conf = openssl_def

# В конец файла:
[openssl_def]
engines = engine_section

[engine_section]
gost = gost_section

[gost_section]
engine_id = gost
dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/gost.so
default_algorithms = ALL
```

### Проверка

```bash
openssl engine -v gost
# Ожидается: (gost) Reference implementation of GOST engine
```

---

## 🏗️ Сборка

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

После сборки в `build/` появятся:
- `gost_server` — сервер
- `gost_client` — клиент
- `gen_certs`   — генератор ключей и тесты

---

## 🚀 Запуск

### Автоматически (всё сразу):
```bash
bash run_demo.sh
```

### Вручную:

**Терминал 1 — сервер:**
```bash
./build/gost_server 7777
```

**Терминал 2 — тесты алгоритмов:**
```bash
mkdir -p certs
./build/gen_certs certs/
```

**Терминал 2 — клиент:**
```bash
./build/gost_client 127.0.0.1 7777 "Моё зашифрованное сообщение"
```

---

## 🔐 Протокол рукопожатия

```
Клиент                                          Сервер
  │                                               │
  │──── ClientHello ──────────────────────────►  │
  │  sign_pubkey_pem   [ГОСТ 34.10-2018]          │
  │  vko_pubkey_pem    [VKO ГОСТ Р 34.10-2012]    │
  │  nonce (32 байта)                             │
  │                                               │
  │  ◄─────────────────────────── ServerHello ───│
  │    sign_pubkey_pem  [ГОСТ 34.10-2018]         │
  │    vko_pubkey_pem   [VKO ГОСТ Р 34.10-2012]   │
  │    ukm (8 байт)     [VKO]                     │
  │    server_nonce                               │
  │    signature        [ГОСТ 34.10-2018]         │
  │                                               │
  │  [VKO] Выработка сессионного ключа            │  [VKO] Выработка сессионного ключа
  │  deriveSharedKey(client_vko, server_vko, ukm) │  deriveSharedKey(server_vko, client_vko, ukm)
  │  → session_key (32 байта)                     │  → session_key (32 байта) [одинаковый!]
  │                                               │
  │──── ClientFinish ─────────────────────────►  │
  │  signature          [ГОСТ 34.10-2018]         │  [ГОСТ 34.10-2018] Верификация подписи
  │  iv                 [ГОСТ 34.13-2018]         │
  │  Кузнечик-CTR(сообщение) [ГОСТ 34.12-2018]   │  [ГОСТ 34.12+34.13] Дешифровка
  │  HMAC-Стрибог(cipher)    [ГОСТ 34.11-2018]   │  [ГОСТ 34.11-2018] Проверка HMAC
  │                                               │
  │  ◄──────────────────────────── ServerAck ────│
  │    iv               [ГОСТ 34.13-2018]         │
  │    Кузнечик-CTR(ответ)  [ГОСТ 34.12-2018]    │
  │    HMAC-Стрибог(cipher) [ГОСТ 34.11-2018]    │
```

---

## 📍 Карта использования ГОСТ-функций в коде

### `gost_utils.hpp` / `gost_utils.cpp`

| Класс/функция | Стандарт | Описание |
|---|---|---|
| `GostHash::hash256()` | ГОСТ 34.11-2018 | Стрибог-256: `EVP_get_digestbyname("md_gost12_256")` |
| `GostHash::hash512()` | ГОСТ 34.11-2018 | Стрибог-512: `EVP_get_digestbyname("md_gost12_512")` |
| `GostHash::hmac256()` | ГОСТ 34.11-2018 | HMAC-Стрибог-256 через `HMAC(md, ...)` |
| `GostSign::generateKeyPair()` | ГОСТ 34.10-2018 | `EVP_PKEY_CTX_new_id(nid_gost2012_256)` + `EVP_PKEY_keygen()` |
| `GostSign::sign()` | ГОСТ 34.10-2018 + 34.11-2018 | `EVP_DigestSignInit(md_gost12_256)` + `EVP_DigestSignFinal()` |
| `GostSign::verify()` | ГОСТ 34.10-2018 + 34.11-2018 | `EVP_DigestVerifyInit()` + `EVP_DigestVerifyFinal()` |
| `GostVKO::generateVKOKeyPair()` | VKO ГОСТ Р 34.10-2012 | `EVP_PKEY_CTX_ctrl_str("paramset", "XA")` |
| `GostVKO::deriveSharedKey()` | VKO ГОСТ Р 34.10-2012 | `EVP_PKEY_derive_init()` + `EVP_PKEY_CTRL_SET_IV(ukm)` + `EVP_PKEY_derive()` |
| `GostCipher::kuznyechikEncryptCTR()` | ГОСТ 34.12-2018 + 34.13-2018 | `EVP_get_cipherbyname("kuznyechik-ctr")` |
| `GostCipher::kuznyechikEncryptCBC()` | ГОСТ 34.12-2018 + 34.13-2018 | `EVP_get_cipherbyname("kuznyechik-cbc")` |
| `GostCipher::magmaEncryptCTR()` | ГОСТ 34.12-2018 + 34.13-2018 | `EVP_get_cipherbyname("magma-ctr")` |

---

## 📚 Ссылки

- [gost-engine (GitHub)](https://github.com/gost-engine/engine) — реализация ГОСТ для OpenSSL
- [RFC 7836](https://datatracker.ietf.org/doc/html/rfc7836) — VKO ГОСТ Р 34.10-2012
- [RFC 4357](https://datatracker.ietf.org/doc/html/rfc4357) — Additional Cryptographic Algorithms for ГОСТ
- [ГОСТ 34.10-2018](https://www.tc26.ru/standard/gost/GOST_R_3410-2012.pdf) — ЭЦП
- [ГОСТ 34.11-2018](https://www.tc26.ru/standard/gost/GOST_R_34_11-2012.pdf) — Стрибог
- [ГОСТ 34.12-2018](https://tc26.ru/standard/gost/GOST_R_3412-2015.pdf) — Кузнечик/Магма
