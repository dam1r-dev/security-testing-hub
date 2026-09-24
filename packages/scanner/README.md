# security-hub-scanner

The core Tree-sitter parsing, taint-analysis and rule engine behind
[`security-hub`](https://www.npmjs.com/package/security-hub) (the CLI).
Most people want the CLI, not this package directly — but if you're
building your own tooling on top (a custom reporter, an editor
extension, a different CLI), this is the library.

Full docs, rule reference and the source live in the main repo:
**https://github.com/dam1r-dev/security-testing-hub**

## Usage

```ts
import { scanPath, computeScore } from "security-hub-scanner";

const summary = scanPath("./my-app");
const score = computeScore(summary);
console.log(`${score.value}/100 (${score.color})`, summary.findingsCount, "finding(s)");
```

See [docs/rules.md](https://github.com/dam1r-dev/security-testing-hub/blob/main/docs/rules.md)
for what each rule detects and its known false-positive/negative shapes.

## License

MIT
