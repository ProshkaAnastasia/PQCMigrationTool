# Architecture — PQC Migration Tool v2.0

## Модульная структура

```
pqc-migration-tool/
├── cmake/FindLibClang.cmake        ← CMake-модуль поиска libclang (LLVM 15–20)
├── CMakeLists.txt                  ← Сборка: C++17, FetchContent(json), OpenSSL, libclang
├── data/
│   └── vulnerable_functions.json  ← База уязвимостей (OpenSSL + Crypto++ + ГОСТ)
├── include/pqc/
│   ├── config.hpp                 ← AppConfig + CLI-парсер
│   ├── cbom.hpp                   ← CycloneDX 1.5 CBOM-типы
│   ├── vuln_database.hpp          ← VulnDatabase (JSON-база, merge-поддержка)
│   ├── project_scanner.hpp        ← ILanguagePlugin + ProjectScanner
│   ├── code_analyzer.hpp          ← ICodeAnalyzer (интерфейс) + Finding
│   ├── regex_analyzer.hpp         ← RegexAnalyzer : ICodeAnalyzer
│   ├── token_analyzer.hpp         ← TokenAnalyzer (fallback, без зависимостей)
│   ├── ast_analyzer.hpp           ← ASTAnalyzer : ICodeAnalyzer (libclang)
│   ├── cert_analyzer.hpp          ← CertAnalyzer + CertInfo (OpenSSL X.509)
│   ├── risk_assessor.hpp          ← RiskAssessor + RiskReport + FileRiskSummary
│   ├── metrics.hpp                ← MetricsCalculator (precision/recall/F1)
│   └── report_generator.hpp      ← ReportGenerator (CBOM + полный отчёт)
├── src/                           ← 11 .cpp-модулей
└── tests/
    ├── fixtures/
    │   ├── sample_vulnerable.cpp  ← Тестовый файл с 10 известными уязвимостями
    │   └── ground_truth.json      ← Эталонные находки для расчёта метрик
    ├── unit/                      ← 6 наборов юнит-тестов
    └── integration/               ← 1 интеграционный тест
```

---

## Pipeline

```
AppConfig::parse(argc, argv)
    │
    ▼
VulnDatabase::load(db.json)
    merge_json() ← --extra-db
    │
    ▼
ProjectScanner::scan(source_path)
    • ILanguagePlugin::matches()  →  CppLanguagePlugin / CMakeLanguagePlugin / CertFilePlugin
    • categorize()                →  SOURCE | HEADER | TEST | BUILD | CERTIFICATE
    → ProjectInventory { files[], language_stats }
    │
    ▼ (выбор режима)
    ┌─────────────────────────────────────┐
    │  -m regex         │   -m ast        │
    │  RegexAnalyzer    │   ASTAnalyzer   │
    │  • compile RE     │   #ifdef        │
    │  • построчный     │   PQC_HAS_LIBCLANG
    │    скан           │   ┌──────────────────────────────────┐
    │  • skip //        │   │ try_libclang():                  │
    │  • context func   │   │  clang_createIndex()             │
    │    (walkback)     │   │  clang_parseTranslationUnit()    │
    │                   │   │  clang_visitChildren(ast_visitor)│
    │                   │   │  VisitData: scope stack          │
    │                   │   │  CXCursor_CallExpr → Finding     │
    │                   │   │  context_fn / context_cls / ns   │
    │                   │   │  clang_Cursor_getNumArguments()  │
    │                   │   │  clang_disposeTranslationUnit()  │
    │                   │   └──────────────────────────────────┘
    │                   │   #else: fallback TokenAnalyzer      │
    └─────────────────────────────────────┘
    → std::vector<Finding>
    │
    ▼
CertAnalyzer::analyze(cert_path)       ← если --cert задан
    • PEM_read_X509 / d2i_X509_fp
    • EVP_PKEY_base_id() → тип
    • EVP_PKEY_bits() → размер
    • assess_algorithm() → CertQuantumRisk
    → std::vector<CertInfo>
    │
    ▼
RiskAssessor::assess(findings, inv, certs)
    For each Finding:
    • analyze_context() → ContextFactors:
        is_network_facing  (+30%)
        is_persistent_data (+25%)
        is_key_material    (+20%)
        is_in_loop         (+10%)
        is_test_code       (-60%)
        call_frequency>5   (+10%)
    • compute_risk() → RiskScore { final_score = min(10, base × multipliers) }
    • build_action() → MigrationAction { replacement from DB }
    • sort_by_risk_desc()
    • aggregate_by_file() → file_summaries
    → RiskReport { migration_plan[], file_summaries{}, nist_readiness }
    │
    ▼ (опционально)
MetricsCalculator::compute(findings, ground_truth)
    • Match by (function_name, file_path, line ± tolerance)
    → AnalysisMetrics { precision, recall, F1 }
    │
    ▼
ReportGenerator::generate()
    • build_cbom()           → pqc_cbom.json  (CycloneDX 1.5)
    • build_full_report()    → pqc_report.json
        ├── findings[]
        ├── certificate_analysis
        ├── risk_assessment     (migration_plan, file_risk_summaries)
        ├── nist_compliance     (FIPS 203/204/205, IR 8547, 5 фаз)
        ├── tc26_compliance     (ГОСТ, VKO, гибридная схема)
        └── analysis_metrics?  (precision/recall/F1, если --metrics)
```

---

## Ключевые компоненты

### ASTAnalyzer (libclang)

Использует `clang-c/Index.h` (официальный C API libclang, доступен с LLVM 10+).

**Visitor с ручной рекурсией и отслеживанием scope:**

```cpp
CXChildVisitResult ast_visitor(CXCursor cursor, CXCursor, CXClientData data) {
    // 1. Пропустить системные заголовки
    if(clang_Location_isInSystemHeader(loc)) return CXChildVisit_Continue;
    // 2. Пропустить файлы, не принадлежащие нашему .cpp
    if(canonical(file) != canonical(vd->file_path)) return CXChildVisit_Continue;
    // 3. Сохранить scope, обновить если FunctionDecl/ClassDecl/Namespace
    std::string sf=vd->cur_fn, sc=vd->cur_cls, sn=vd->cur_ns;
    // 4. Если CXCursor_CallExpr — lookup в VulnDatabase → Finding
    //    clang_getCursorReferenced() → имя функции
    //    clang_Cursor_getNumArguments() → аргументы
    // 5. Рекурсия вручную (сохраняет scope)
    clang_visitChildren(cursor, ast_visitor, data);
    // 6. Восстановить scope
    if(scope_changed) { vd->cur_fn=sf; vd->cur_cls=sc; vd->cur_ns=sn; }
    return CXChildVisit_Continue;  // не позволяем родителю повторно рекурсировать
}
```

**Преимущество над регексом:**
- Нет ложных срабатываний из строк/комментариев
- Извлечение имени вызывающей функции + класса + пространства имён
- Аргументы вызова через API (не текстовый парсинг)
- Обработка перегруженных и шаблонных функций

**Graceful fallback:** при ошибке парсинга (недостающие заголовки) переходит на TokenAnalyzer.

---

### VulnDatabase

- Загрузка из JSON (`load()`)
- Слияние нескольких баз (`merge_json()`)
- O(1) поиск по имени + псевдонимам (хеш-карта)
- Без перекомпиляции: добавить библиотеку = добавить раздел в JSON

### RiskAssessor

**Формула оценки риска:**

```
final_score = min(10, base_score × Π(multipliers))
```

| Фактор контекста | Мультипликатор |
|-----------------|---------------|
| Сетевой код (`/tls/`, `/ssl/`, `/net/`) | ×1.30 |
| Хранение данных (`/db/`, `/storage/`) | ×1.25 |
| Ключевой материал | ×1.20 |
| В цикле (`for`, `while`) | ×1.10 |
| Высокая частота (>5 вызовов) | ×1.10 |
| Тестовый код | ×0.40 |

**HNDL-угроза** отмечается для `asymmetric_encryption` / `key_exchange` в сетевом или хранилищном контексте.

**ТК 26 transition note** автоматически добавляется в план миграции из поля `tc26_reference` базы данных.

---

## Масштабирование на новые языки

```cpp
class GoLanguagePlugin : public pqc::ILanguagePlugin {
    std::string language_name() const override { return "go"; }
    bool matches(const std::filesystem::path& p) const override {
        return p.extension() == ".go";
    }
    pqc::FileCategory categorize(const std::filesystem::path& p) const override {
        return p.string().find("_test.go") != std::string::npos
            ? pqc::FileCategory::TEST : pqc::FileCategory::SOURCE;
    }
};
// Одна строка в main.cpp:
scanner.register_plugin(std::make_unique<GoLanguagePlugin>());
```

---

## Соответствие ТЗ (ВКР)

| Задача ТЗ | Реализация |
|-----------|-----------|
| Анализ угроз | `data/vulnerable_functions.json` + ссылки NIST/ТК 26 |
| Инвентаризация файлов | `ProjectScanner` + `ILanguagePlugin` (C/C++, CMake, X.509) |
| Regex-анализ | `RegexAnalyzer` с дедупликацией |
| AST-анализ (libclang) | `ASTAnalyzer` + `ast_visitor` с отслеживанием scope |
| Анализ сертификатов | `CertAnalyzer` (OpenSSL X.509 API, PEM+DER) |
| Оценка рисков | `RiskAssessor` с мультипликаторами контекста |
| Агрегатор по файлам | `FileRiskSummary` в `RiskReport::file_summaries` |
| Приоритизированный план | `MigrationAction[]` sorted by `final_score` desc |
| CBOM (CycloneDX 1.5) | `cbom.hpp`, `report_generator.cpp::build_cbom()` |
| JSON-отчёт | `pqc_report.json` с секциями nist/tc26_compliance |
| NIST IR 8547 (5 фаз) | `nist_compliance_section()` в отчёте |
| ТК 26 | `tc26_compliance_section()` + `tc26_reference` в каждом Finding |
| Тестирование | 6 unit-suite + 1 integration + ground_truth.json |
| Метрики (precision/recall/F1) | `MetricsCalculator` + `--metrics` флаг |
