import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src";

jest.setTimeout(60_000);

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-include-"));
  for (const [name, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), body);
  }
  return dir;
}

function xss(dir: string): Array<{ file: string; message: string }> {
  return scanPath(dir, { config: false }).results.flatMap((r) => r.findings.filter((f) => f.ruleId === "xss").map((f) => ({ file: path.basename(r.file), message: f.message })));
}

const FLASK = "from flask import Flask, request, render_template\napp = Flask(__name__)\n\n@app.route('/')\ndef index():\n    bio = request.args.get('bio')\n    return render_template('page.html', bio=bio)\n";

describe("an include that is handed the value under another name (round 18)", () => {
  it("Jinja/Django: {% include 'row.html' with item=bio %} and |safe in the include", () => {
    const dir = project({
      "app.py": FLASK,
      "templates/page.html": "<h1>Profile</h1>{% include 'row.html' with item=bio %}\n",
      "templates/row.html": "<p>{{ item|safe }}</p>\n",
    });
    const hits = xss(dir).filter((h) => h.file === "app.py");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toMatch(/row\.html:1/);
  });

  it("Twig: with {item: bio} only", () => {
    const dir = project({
      "app.py": FLASK,
      "templates/page.html": "{% include 'row.html' with {item: bio} only %}\n",
      "templates/row.html": "<p>{{ item|raw }}</p>\n",
    });
    expect(xss(dir).filter((h) => h.file === "app.py")).toHaveLength(1);
  });

  it("silent when the include escapes the renamed value, or the value is not the one handed over", () => {
    const escaped = project({
      "app.py": FLASK,
      "templates/page.html": "{% include 'row.html' with item=bio %}\n",
      "templates/row.html": "<p>{{ item }}</p>\n",
    });
    expect(xss(escaped)).toHaveLength(0);
    const other = project({
      "app.py": FLASK,
      "templates/page.html": "{% include 'row.html' with item='static' %}\n",
      "templates/row.html": "<p>{{ item|safe }}</p>\n",
    });
    expect(xss(other)).toHaveLength(0);
  });

  it("Blade: @include('row', ['item' => $bio]) and {!! $item !!} in the include", () => {
    const controller = "<?php\nclass ProfileController {\n  public function show(Request $request) {\n    $bio = $request->input('bio');\n    return view('page', ['bio' => $bio]);\n  }\n}\n";
    const dir = project({
      "app/Http/Controllers/ProfileController.php": controller,
      "resources/views/page.blade.php": "<h1>Profile</h1>\n@include('row', ['item' => $bio])\n",
      "resources/views/row.blade.php": "<p>{!! $item !!}</p>\n",
    });
    const hits = xss(dir).filter((h) => h.file === "ProfileController.php");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toMatch(/row\.blade\.php:1/);
    const escaped = project({
      "app/Http/Controllers/ProfileController.php": controller,
      "resources/views/page.blade.php": "@include('row', ['item' => $bio])\n",
      "resources/views/row.blade.php": "<p>{{ $item }}</p>\n",
    });
    expect(xss(escaped)).toHaveLength(0);
  });
});

describe("Django: parameters of an include() prefix reach the included views (round 18)", () => {
  const hits = (dir: string): string[] => scanPath(dir, { config: false }).results.flatMap((r) => r.findings.map((f) => `${path.basename(r.file)}:${f.location.startLine}:${f.ruleId}`));
  const views = [
    "from django.db import connection",
    "def profile(request, user_id):",
    "    connection.cursor().execute(f\"SELECT * FROM t WHERE id = {user_id}\")",
    "def by_name(request, name):",
    "    connection.cursor().execute(f\"SELECT * FROM t WHERE n = '{name}'\")",
    "",
  ].join("\n");

  it("a number in the prefix is a number in the view; a plain <name> is still text", () => {
    const dir = project({
      "urls.py": "from django.urls import path, include\nurlpatterns = [\n    path('users/<int:user_id>/', include('users.urls')),\n    path('x/<name>/', include('users.urls')),\n]\n",
      "users/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [\n    path('', views.profile),\n    path('by/', views.by_name),\n]\n",
      "users/views.py": views,
    });
    const found = hits(dir);
    expect(found).not.toContain("views.py:3:sql-injection"); // user_id: <int:...> in the prefix
    expect(found).toContain("views.py:5:sql-injection"); // name: one segment is still text for SQL
  });

  it("an include with no parameters in its prefix changes nothing (the view keeps the default: any text)", () => {
    const dir = project({
      "urls.py": "from django.urls import path, include\nurlpatterns = [path('users/', include('users.urls'))]\n",
      "users/urls.py": "from django.urls import path\nfrom . import views\nurlpatterns = [path('', views.profile)]\n",
      "users/views.py": views,
    });
    expect(hits(dir)).toContain("views.py:3:sql-injection");
  });
});
