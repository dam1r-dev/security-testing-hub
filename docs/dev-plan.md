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
- ✅ **Phase 3/4 (5 базовых типов атак)** — SQLi, XSS, Command Injection, Path Traversal, CSRF реализованы
  как первая версия (глубже per-type edge cases — ещё предстоит по мере роста набора тестов)
- ✅ **Phase 5 (CLI + SARIF)** — `security-hub scan` с text/json/sarif выводом, `--fail-on` для CI
- ✅ **Phase 6 (Docker Lab)** — SQL Injection lab (`labs/sql-injection/`): уязвимый + safe-mode
  в одном образе (переключение `SAFE_MODE` env), E2E-скрипт (`labs/sql-injection/e2e.js`)
  доказывает эксплуатируемость И то, что фикс реально закрывает баг, CLI-команда `security-hub lab`,
  отдельная CI-джоба. Остальные лабы (XSS, CSRF) — после MVP.
- 🟡 **Phase 7 (Documentation)** — README (EN+RU), `docs/rules.md`, `docs/attack-playbook.md` (EN/RU/KK) есть; полные гайды — в процессе
- 🟡 **Phase 8 (Testing + CSRF Lab)** — Jest-тесты для всех анализаторов есть, coverage-таргет и Docker-лабы — не начато
- ✅ **Phase 9 (частично)** — CONTRIBUTING.md, CODE_OF_CONDUCT.md, PR/Issue шаблоны, CI на GitHub Actions

### Инцидент: CI падал на каждом коммите (найдено и исправлено)

С самого первого коммита CI на GitHub Actions детерминированно падал
(8 из 11 тестовых файлов scanner), хотя локально (Windows, WSL Ubuntu
Node 20/22) все тесты всегда проходили. Причина: Jest даёт каждому
тестовому файлу свой модульный реестр, но нативный аддон tree-sitter
грузится один раз на процесс — повторный `require` того же нативного
биндинга из ВТОРОГО тестового файла внутри уже "занятого" воркер-процесса
даёт битое дерево (`rootNode` становится `undefined`/некорректным).
Подтверждено экспериментально: `--runInBand` (1 процесс) — проходит
только самый первый файл; чем больше воркеров, тем больше файлов
"повезло" быть первыми в своём процессе. Пересборка из исходников не
помогла (стало хуже) — дело не в prebuild/glibc. Фикс: `maxWorkers: 32`
в `jest.config.js` — воркеров больше, чем файлов, поэтому каждый файл
гарантированно получает свежий процесс.

### Инцидент 2: сканер падал/врал на реальных проектах (найдено и исправлено)

По запросу «слабо, надо больше и лучше, надо сканить целый проект» —
прогнал сканер на реальном Next.js-проекте (86 файлов) и нашёл два
самостоятельных бага:

1. **Крэш всего скана на файлах > ~32KB.** `node-tree-sitter` кидает
   `Invalid argument`, если отдать `.parse()` обычную строку длиннее ~32KB
   (нет непрерывного fast-string буфера у V8). Задело сгенерированные
   Prisma-файлы (34-56KB). Фикс: chunked-reader callback вместо строки —
   но только для файлов больше `SAFE_STRING_LIMIT` (30000 символов), не для
   всех, см. ниже почему.
2. **Более коварный баг: сканер молча пропускал уязвимости в файлах, если
   они не первые в процессе.** При сканировании нескольких файлов подряд
   (даже с `parseFile()` напрямую, без Jest) один из анализаторов на одном
   из файлов мог не найти реальную уязвимость — детерминированно
   воспроизводимо, но какой именно файл/анализатор "терялся" зависело от
   порядка. Подтверждено: `global.gc()` между файлами чинит проблему
   стабильно — баг в GC-таймингах нативного биндинга tree-sitter, не в
   нашей логике (тот же файл + тот же анализатор в полной изоляции всегда
   отрабатывает верно). Фикс: `src/parsers/gc-workaround.ts` — форсирует
   полный GC через трюк `v8.setFlagsFromString('--expose-gc')` без
   необходимости запускать Node с этим флагом. **Важное уточнение:**
   изначально вызов положили только в цикл `scanPath` (по одному на файл),
   но баг оказался шире — он бьёт по ЛЮБОМУ повторному `parser.parse()` в
   процессе, в том числе когда один тестовый файл вызывает `scanSource()`
   несколько раз подряд (без всякого multi-file сканирования). Поймали это,
   когда после добавления новых тестов внезапно упал `sql-injection.test.ts`
   при 5 повторных прогонах. Перенесли вызов внутрь самого `parseSource()`
   — теперь защищён каждый вызов парсера, а не только per-file цикл.
   Регресс-тест: `tests/multi-file-scan.test.ts`.

Заодно добавлена поддержка Next.js App Router как источника данных
(`request.nextUrl.searchParams`, `request.cookies.get()`, `request.json()`)
— до этого сканер понимал только Express-паттерны (`req.params` и т.п.) и
находил 0 находок на любом Next.js-проекте независимо от того, есть там
реальные уязвимости или нет. См. `src/analyzers/sources.ts` и
`examples/vulnerable-nextjs-app/`.

### Итерация 2: CSRF/IDOR/Broken Access Control теперь понимают Next.js

Ранее эти три правила искали только `app.get(...)`/`router.post(...)` —
на Next.js App Router (файловый роутинг) они молчали независимо от того,
защищён роут или нет. Добавлен `src/analyzers/nextjs-routes.ts`:
распознаёт `route.ts`-файлы, извлекает URL-сегменты из **пути файла**
(включая route groups вида `(admin)`, которые не видны в реальном URL, но
являются явным сигналом намерения), находит экспортированные
`GET`/`POST`/`PUT`/`DELETE`/`PATCH`-обработчики.

Отдельное инженерное решение как у специалиста по безопасности:
`broken-access-control` для Next.js перед тем как флагать роут, проверяет
наличие `middleware.ts` в корне проекта с признаками auth-проверки —
в Next.js авторизация часто централизована там через `config.matcher`, а
не в самом route-файле. Не можем проверить, реально ли matcher покрывает
именно этот роут (нужна была бы реализация семантики Next.js matcher —
отдельная большая задача), поэтому решение сознательно консервативное:
любой auth-подобный `middleware.ts` в проекте гасит это правило везде.
Это осознанный trade-off в сторону меньшего числа false positive ценой
пропуска редкого случая "middleware есть, но matcher не покрывает именно этот роут".

Заодно расширены паттерны owner/auth-проверки (`getServerSession`,
`auth()`, `currentUser()` — NextAuth/Clerk) — раньше проверялись только
`req.user`/`req.session`.

**Найденный по пути баг (ирония):** слово "CSRF" в комментарии,
объясняющем уязвимость `transfer.js`/`transfer/route.ts`, само подавляло
её обнаружение — эвристика ищет `/csrf/i` по всему файлу. Оба фикстурных
роута никогда не флагались с первого дня. Исправлено переписыванием
комментариев без этого слова; задокументировано как gotcha в
`docs/rules.md`.

### Итерация 3: оценка 0-100 и HTML-отчёт

По запросу «оценка в процентах, с цветом, плюс лёгкая обёртка/UI» добавлены:

- `output/score.ts` — 0-100, штраф за находку = вес severity × множитель
  confidence (наши же эвристики (csrf/idor/broken-access-control) сами
  репортят `confidence: "low"` — не должны стоить столько же, сколько
  taint-based находка с `confidence: "high"`). Зелёный ≥80, жёлтый 50-79,
  красный <50.
- `output/html.ts` — самодостаточный HTML-отчёт (без сервера, без внешних
  ресурсов): SVG-кольцо со счётом, разбивка по severity, фильтруемый список
  находок. Формат `--format html` в CLI, по умолчанию пишет в
  `security-report.html` (raw HTML в терминал печатать бессмысленно).
- Счёт также показывается в конце `text`-вывода (цветной) и добавлен полем
  `score` в `json`-вывод.
- Важно с точки зрения безопасности самого инструмента: весь текст находок
  (сообщения, код из sink/source) экранируется в HTML-отчёте — иначе
  сканер, показывающий XSS-уязвимость, сам стал бы XSS-уязвимым через
  собственный отчёт. Проверено тестом (`html.test.ts`).

Живая проверка: `examples/vulnerable-express-app` → 0/100 (красный, 19
находок), реальный JumaTime → 100/100 (зелёный, 0 находок).

### Расширение за пределы исходного плана

По запросу (сопоставление с классическим списком из 15 категорий веб-атак
— PortSwigger/OWASP-стиль) набор правил расширен с 5 до 11 типов:
добавлены SSRF, IDOR, Broken Access Control, Insecure Role Assignment,
Insecure File Upload и Username Enumeration (последние пять — эвристики
по паттернам/роутам, не taint-анализ). Два класса из списка (2FA bypass,
утечка пароля в теле ответа) статически не детектируются — они
задокументированы как чек-лист для ручного тестирования в
[docs/attack-playbook.md](attack-playbook.md).
