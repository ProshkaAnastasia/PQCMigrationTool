# PQC Migration Tool v2.0

**Инструмент автоматизированного анализа и планирования миграции на постквантовую криптографию**
**NIST IR 8547 | NIST FIPS 203/204/205 | ТК 26**

---

## Быстрая сборка

### Linux (Debian/Ubuntu)

```bash
# Зависимости
sudo apt install cmake g++ libssl-dev libclang-dev git

# Если нужна конкретная версия libclang:
# sudo apt install libclang-18-dev llvm-18-dev

# Сборка
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel $(nproc)
# → build/pqc-migration-tool
```

### macOS

```bash
brew install cmake openssl@3 llvm
cmake -B build -DCMAKE_BUILD_TYPE=Release \
      -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) \
      -DLLVM_DIR=$(brew --prefix llvm)/lib/cmake/llvm
cmake --build build --parallel $(sysctl -n hw.ncpu)
```

### Windows (vcpkg + LLVM)

```powershell
vcpkg install openssl:x64-windows
winget install LLVM.LLVM
cmake -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

### Сборка без libclang (деградация в token-режим)

```bash
cmake -B build -DPQC_REQUIRE_LIBCLANG=OFF
cmake --build build
```

---

## Запуск

```bash
# Базовый (regex-режим)
./build/pqc-migration-tool -s /path/to/project

# Полный аудит: libclang AST + сертификаты + verbose
./build/pqc-migration-tool \
  -s /path/to/project \
  -c /etc/ssl/certs \
  -m ast \
  -o report.json \
  --cbom-output cbom.json \
  -v

# С кастомными include-путями для libclang
./build/pqc-migration-tool \
  -s /path/to/project \
  -m ast \
  -I /path/to/project/include \
  -I /usr/local/include/mylib

# Оценка точности (precision/recall)
./build/pqc-migration-tool \
  -s tests/fixtures \
  -m ast \
  --metrics \
  --ground-truth tests/fixtures/ground_truth.json

# Дополнительная база уязвимостей
./build/pqc-migration-tool -s . --extra-db my_custom_db.json

# Только CBOM (без плана миграции)
./build/pqc-migration-tool -s . --cbom-only

# Удалённый проект через sshfs
sshfs user@server:/remote/project /tmp/remote
./build/pqc-migration-tool -s /tmp/remote -m ast
```

## Параметры CLI

| Флаг | Описание |
|------|---------|
| `-s, --source` | Путь к исходному коду (обязателен) |
| `-c, --cert` | Файл/директория сертификатов X.509 |
| `-d, --db` | JSON-база уязвимостей |
| `-m, --mode` | `regex` или `ast` |
| `-I, --include` | Include-путь для libclang (повторяемый) |
| `-o, --output` | Путь к полному JSON-отчёту |
| `--cbom-output` | Путь к CBOM-файлу |
| `--extra-db` | Дополнительная JSON-база (merge) |
| `--metrics` | Вычислить precision/recall/F1 |
| `--ground-truth` | JSON-файл с эталонными находками |
| `--cbom-only` | Только CBOM, без анализа рисков |
| `--skip-cert` | Пропустить анализ сертификатов |
| `-v, --verbose` | Подробный вывод |

---

## Запуск тестов

```bash
cmake -B build -DPQC_BUILD_TESTS=ON
cmake --build build
cd build && ctest --output-on-failure

# Или напрямую:
./build/tests/pqc_unit_tests
./build/tests/pqc_integration_tests
```

---

## Расширение базы данных

`data/vulnerable_functions.json` — без перекомпиляции:

```json
{
  "libraries": {
    "mylib": {
      "display_name": "MyLib",
      "functions": [{
        "id": "mylib-rsa",
        "name": "mylib_rsa_encrypt",
        "aliases": [],
        "category": "asymmetric_encryption",
        "algorithm": "RSA",
        "quantum_vulnerability": "high",
        "risk_score": 9.5,
        "description": "...",
        "nist_reference": "NIST SP 800-131A Rev.2",
        "tc26_reference": "ТК 26: ...",
        "deprecation_url": "https://...",
        "patterns": ["mylib_rsa_encrypt\\s*\\("],
        "replacements": [{ "function_name": "OQS_KEM_encaps", "library": "liboqs",
          "standard": "FIPS 203", "algorithm": "ML-KEM-768" }]
      }]
    }
  }
}
```

## Добавление нового языка

```cpp
class PythonPlugin : public pqc::ILanguagePlugin {
public:
    std::string language_name() const override { return "python"; }
    bool matches(const std::filesystem::path& p) const override { return p.extension()==".py"; }
    pqc::FileCategory categorize(const std::filesystem::path& p) const override {
        return p.string().find("test_")!=std::string::npos ? pqc::FileCategory::TEST : pqc::FileCategory::SOURCE;
    }
};
// В main.cpp:
scanner.register_plugin(std::make_unique<PythonPlugin>());
```

---

## Стандарты

| NIST | Алгоритм | Назначение |
|------|---------|-----------|
| FIPS 203 | ML-KEM (CRYSTALS-Kyber) | Инкапсуляция ключа |
| FIPS 204 | ML-DSA (CRYSTALS-Dilithium) | Цифровая подпись |
| FIPS 205 | SLH-DSA (SPHINCS+) | Подпись (hash-based) |
| draft FIPS 206 | FN-DSA (Falcon) | Компактная подпись |

ТК 26 рекомендует **гибридный подход** в переходный период:
применять классические (ГОСТ Р 34.10-2012) и постквантовые алгоритмы совместно.
