#!/usr/bin/env bash
# run_demo.sh — скрипт демонстрации проекта
# Использование: bash run_demo.sh [port]
set -e

BUILD_DIR="build"
CERTS_DIR="certs"
PORT=${1:-7777}

echo "════════════════════════════════════════════════════"
echo "  GOST Client-Server Demo — Скрипт запуска"
echo "════════════════════════════════════════════════════"

# Проверяем наличие OPENSSL_CONF
if [ -z "$OPENSSL_CONF" ] && ! openssl engine gost 2>/dev/null | grep -q gost; then
    echo "⚠ Переменная OPENSSL_CONF не задана."
    echo "  Если gost-engine установлен, но не в openssl.cnf, задайте:"
    echo "  export OPENSSL_CONF=/path/to/openssl_with_gost.cnf"
    echo ""
fi

# Находим cmake
CMAKE_BIN=$(which cmake 2>/dev/null || \
            python3 -c "import cmake,os; print(os.path.join(os.path.dirname(cmake.__file__),'data','bin','cmake'))" 2>/dev/null || \
            find ~/.local /usr/local -name cmake -type f 2>/dev/null | head -1)

if [ -z "$CMAKE_BIN" ]; then
    echo "❌ cmake не найден. Установите cmake или: pip3 install cmake"
    exit 1
fi
echo "CMake: $CMAKE_BIN ($($CMAKE_BIN --version | head -1))"

# Сборка
echo ""
echo "[1/3] Сборка проекта..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
$CMAKE_BIN .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
cd ..

echo ""
echo "[2/3] Генерация ключей и тесты алгоритмов..."
mkdir -p "$CERTS_DIR"
"$BUILD_DIR/gen_certs" "$CERTS_DIR"

echo ""
echo "[3/3] Запуск сервера и клиента..."
"$BUILD_DIR/gost_server" "$PORT" &
SRV_PID=$!
echo "Сервер PID: $SRV_PID (порт $PORT)"
sleep 1.5

"$BUILD_DIR/gost_client" 127.0.0.1 "$PORT" "Тестовое сообщение через ГОСТ!" || true

sleep 0.3
kill $SRV_PID 2>/dev/null || true
echo ""
echo "════════════════════════════════════════════════════"
echo "  ✓ Демонстрация завершена!"
echo "════════════════════════════════════════════════════"
