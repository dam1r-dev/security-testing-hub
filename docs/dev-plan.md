# Development Plan (V3 FINAL — Reality Check)

_Source: `Security_Testing_Hub_Development_Plan_V3_FINAL.docx`, kept here in
Markdown for version control. Original author's language (Russian) preserved._

Damir Panzhazov | Narxoz University | Сентябрь 2026

## ⚡ Главные изменения V2 → V3

### 1️⃣ Только JavaScript/TypeScript для MVP
**Было:** JS + Python + PHP одновременно
**Стало:** Только Node.js/Express приложения. Python & PHP → Advanced Features (Phase 7+)
**Почему:** семантика языков сильно отличается, Tree-sitter парсер и правила
Taint-анализа нужны отдельные для каждого языка — один язык = x3 сокращение сложности.

### 2️⃣ Упрощённый Taint Analysis (Intra-procedural)
**Было:** межпроцедурный анализ (inter-procedural) — отслеживание данных через файлы и функции
**Стало:** внутри одной функции (intra-procedural)

Находим (SQL Injection в Express):
```js
app.get("/user/:id", (req, res) => {
  const id = req.params.id;  // SOURCE (untrusted)
  const query = `SELECT * FROM users WHERE id = ${id}`;  // SINK (dangerous)
  db.query(query);  // ALERT!
})
```

Не находим (пока):
```js
// sanitize.js
export const sanitize = (input) => { /* очищаем */ }

// controller.js
const id = sanitize(req.params.id);  // Не отслеживаем вызовы функций
```

**Выигрыш:** проще писать правила, быстрее парсить код, меньше ошибок.
False positives выше, но управляемы.

### 3️⃣ Фаза 0: Dedicated Learning Week
Полная неделя (40 часов... позже скорректировано до 20ч при 4ч/день) на
Tree-sitter API, ts-query, AST для JavaScript, первый простой парсер.

### 4️⃣ Снижение темпа: 4 часа в день
**Было:** 5-6 часов/день × 8-9 недель
**Стало:** 4 часа/день × 10-12 недель
- Phase 0 (Learning): 1 неделя × 5 дней × 4ч = 20 часов
- Phase 1-9 (Development): ~9 недель × 5 дней × 4ч = ~180 часов
- **Итого:** ~182-200 часов за 10-12 недель

### 5️⃣ Реалистичные метрики успеха
**Было:** FP < 10%, FN < 5%
**Стало (V1 MVP):** FP < 25-30%, FN < 5-10%
Контекст: Snyk (enterprise) ~15-20% FP, SonarQube ~20-30% FP.

## ⏱️ Таймлайн V3

| Phase | Title | Duration | Hours | Deliverable |
|---|---|---|---|---|
| 0 | Learning Week | 1 неделя (5×4ч) | 20ч | Tree-sitter, AST, ts-query basics |
| 1 | Architecture Setup | 4-5 дней | 18ч | Repo structure, TypeScript setup, Tree-sitter config |
| 2 | Parser + Basic Taint | 5-6 дней | 22ч | Tree-sitter интеграция, intra-proc taint для 1 атаки |
| 3 | SQL Injection Deep | 4-5 дней | 18ч | SQL Injection полностью (regex + taint hybrids) |
| 4 | XSS + Command Inject | 5-6 дней | 22ч | Оставшиеся 3 атаки (XSS, Command, Path) |
| 5 | CLI + SARIF Output | 4-5 дней | 18ч | Команды, JSON, SARIF форматирование |
| 6 | Docker Lab (SQL) | 4-5 дней | 18ч | SQL Injection lab + E2E тест |
| 7 | Documentation | 3-4 дня | 14ч | README, гайды на русском |
| 8 | Testing + CSRF Lab | 4-5 дней | 18ч | Jest тесты (70%+), CSRF lab, последняя E2E |
| 9 | Polish + Open Source | 3-4 дня | 14ч | CONTRIBUTING.md, шаблоны PR/Issues, финальный cleanup |

**Итого:** 10-11 недель, ~182 часа.

## 🏗️ Упрощённая архитектура (V3)

```
packages/scanner/
├── src/
│   ├── parsers/
│   │   ├── ast-parser.ts        # Tree-sitter для JavaScript
│   │   └── utils.ts             # Helper функции для AST
│   ├── analyzers/
│   │   ├── base-analyzer.ts     # Base class для всех анализаторов
│   │   ├── sql-injection.ts
│   │   ├── xss.ts
│   │   ├── command-injection.ts
│   │   ├── path-traversal.ts
│   │   └── csrf.ts
│   ├── taint/
│   │   └── simple-taint.ts      # Интра-procedural taint tracking
│   └── output/
│       └── sarif.ts             # SARIF JSON форматирование
```

Simple Taint Tracking (псевдокод):
```js
function analyzeFunctionBody(funcNode, sourcePatterns, sinkPatterns) {
  const sources = findNodes(funcNode, sourcePatterns);  // req.params, etc
  const sinks = findNodes(funcNode, sinkPatterns);      // db.query, etc

  for (const source of sources) {
    const taintedVars = getAliases(source);  // Какие переменные получают это значение
    for (const sink of sinks) {
      if (sink.usesAnyOf(taintedVars)) {  // Используется ли tainted data в sink?
        return VULNERABILITY_FOUND;
      }
    }
  }
}
```

## ✅ MVP Success Criteria (V3)

**Scanning Quality**
- 5 типов атак для JavaScript/TypeScript
- False Positive Rate: 25-30% (приемлемо для v1)
- False Negative Rate: < 10%
- Тестировано на 10+ реальных Node.js проектах

**Deliverables**
- Working CLI (scan, lab, docs, report команды)
- SARIF JSON output (GitHub совместимость)
- 2 Docker labs (SQL Injection, XSS) с E2E тестами
- Documentation: гайды, API, примеры
- 70%+ Jest test coverage
- CONTRIBUTING.md, CODE_OF_CONDUCT.md

**Community**
- GitHub repo открыт для contributions
- Первые 30+ GitHub stars
- Работает с Express/Fastify/NestJS приложениями

## ⚠️ Риски и mitigation (V3)

| Риск | Уровень | Mitigation |
|---|---|---|
| Tree-sitter сложнее чем казалось | СРЕДНИЙ | Добавлена Фаза 0 на обучение |
| Taint анализ всё ещё непростой | ВЫСОКИЙ | Упрощённый intra-proc анализ, inter-proc → v2 |
| Выгорание если темп выше | СРЕДНИЙ | 4ч/день, можно снизить до 3ч без паники |
| False positives > 30% | СРЕДНИЙ | Нормально для v1, filtering после MVP |
| Только 1 язык | НИЗКИЙ | Хорошая основа для v2 |
| Docker labs слишком сложные | СРЕДНИЙ | Начнём с одного (SQL), остальные после MVP |

## Реализация в этом репозитории — статус

- ✅ **Phase 1 (Architecture Setup)** — монорепо, TypeScript, Tree-sitter config
- ✅ **Phase 2 (Parser + Basic Taint)** — `ast-parser.ts`, `simple-taint.ts`, SQL injection analyzer
- ✅ **Phase 3/4 (все 5 типов атак)** — SQLi, XSS, Command Injection, Path Traversal, CSRF реализованы
  как первая версия (глубже per-type edge cases — ещё предстоит по мере роста набора тестов)
- ✅ **Phase 5 (CLI + SARIF)** — `security-hub scan` с text/json/sarif выводом, `--fail-on` для CI
- ⬜ **Phase 6 (Docker Lab)** — не начато
- 🟡 **Phase 7 (Documentation)** — README (EN+RU), `docs/rules.md` есть; полные гайды — в процессе
- 🟡 **Phase 8 (Testing + CSRF Lab)** — Jest-тесты для всех 5 анализаторов есть, coverage-таргет и CSRF lab — не начато
- ✅ **Phase 9 (частично)** — CONTRIBUTING.md, CODE_OF_CONDUCT.md, PR/Issue шаблоны, CI на GitHub Actions
