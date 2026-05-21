#!/usr/bin/env bash
# setup_gost_engine.sh — Установка gost-engine на Debian/Ubuntu/Arch
# Запустите с правами root: sudo bash setup_gost_engine.sh
set -e

OS="unknown"
if [ -f /etc/debian_version ]; then OS="debian"; fi
if [ -f /etc/arch-release ];   then OS="arch";   fi

echo "Обнаружена ОС: $OS"

if [ "$OS" = "debian" ]; then
    apt-get update
    apt-get install -y gcc g++ make cmake git libssl-dev pkg-config

    # Проверяем есть ли готовый пакет
    if apt-cache show libengine-gost-openssl 2>/dev/null | grep -q Package; then
        apt-get install -y libengine-gost-openssl
        echo "gost-engine установлен из репозитория ✓"
    else
        echo "Сборка gost-engine из исходников..."
        git clone https://github.com/gost-engine/engine.git /tmp/gost-engine
        cd /tmp/gost-engine
        git submodule update --init
        mkdir build && cd build
        cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
        make -j"$(nproc)"
        make install
        echo "gost-engine собран и установлен ✓"
    fi

elif [ "$OS" = "arch" ]; then
    pacman -Sy --noconfirm gcc cmake git openssl
    # Из AUR (требует yay/paru)
    if command -v yay &>/dev/null; then
        yay -S --noconfirm openssl-gost-engine
    else
        echo "Установите openssl-gost-engine из AUR вручную"
    fi
fi

# Настройка openssl.cnf
OPENSSL_CNF=$(openssl version -d | grep -oP 'OPENSSLDIR: "\K[^"]+')"/openssl.cnf"
echo "Конфиг OpenSSL: $OPENSSL_CNF"

if ! grep -q "openssl_def" "$OPENSSL_CNF" 2>/dev/null; then
    # Определяем путь к gost.so
    GOST_SO=""
    for p in \
        /usr/lib/x86_64-linux-gnu/engines-3/gost.so \
        /usr/lib/x86_64-linux-gnu/engines-1.1/gost.so \
        /usr/lib/engines-3/gost.so \
        /usr/lib64/engines-3/gost.so \
        /usr/local/lib/engines-3/gost.so; do
        if [ -f "$p" ]; then GOST_SO="$p"; break; fi
    done

    if [ -n "$GOST_SO" ]; then
        sed -i 's/^openssl_conf\s*=\s*openssl_init/openssl_conf = openssl_def\n#openssl_conf = openssl_init/' "$OPENSSL_CNF" 2>/dev/null || \
        sed -i '1i openssl_conf = openssl_def' "$OPENSSL_CNF"

        cat >> "$OPENSSL_CNF" << CNF
[openssl_def]
engines = engine_section

[engine_section]
gost = gost_section

[gost_section]
engine_id = gost
dynamic_path = $GOST_SO
default_algorithms = ALL
CNF
        echo "openssl.cnf настроен ✓"
    else
        echo "⚠ gost.so не найден, настройте openssl.cnf вручную"
    fi
else
    echo "openssl.cnf уже настроен ✓"
fi

echo ""
echo "Проверка:"
openssl engine -v gost 2>&1 | head -5 || echo "⚠ gost engine не виден, перезапустите shell"
