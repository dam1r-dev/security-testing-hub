import { scanSource } from "../src";

const py = (code: string, rule: string, file = "/app/app.py"): string[] => scanSource(code, file).findings.filter((f) => f.ruleId === rule).map((f) => f.ruleId);
const php = (code: string, rule: string, file = "/app/index.php"): string[] => scanSource(`<?php\n${code}\n`, file).findings.filter((f) => f.ruleId === rule).map((f) => f.ruleId);

describe("weak-crypto (Python)", () => {
  it("MD5 / SHA-1 over a password; checksums and SHA-256 are fine", () => {
    expect(py("import hashlib\ndef hash_password(p):\n    return hashlib.md5(p.encode()).hexdigest()\n", "weak-crypto")).toHaveLength(1);
    expect(py("import hashlib\nh = hashlib.sha1(user_password.encode()).hexdigest()\n", "weak-crypto")).toHaveLength(1);
    expect(py('import hashlib\nh = hashlib.new("md5", password.encode())\n', "weak-crypto")).toHaveLength(1);
    expect(py("import hashlib\netag = hashlib.md5(body).hexdigest()\n", "weak-crypto")).toHaveLength(0);
    expect(py("import hashlib\nh = hashlib.sha256(password.encode()).hexdigest()\n", "weak-crypto")).toHaveLength(0);
  });

  it("the random module for a token, a code or a session id", () => {
    expect(py("import random\nreset_token = ''.join(random.choices(chars, k=12))\n", "weak-crypto")).toHaveLength(1);
    expect(py("import random\ndef make_otp():\n    return random.randint(100000, 999999)\n", "weak-crypto")).toHaveLength(1);
    expect(py("import random\ncolor = random.choice(colors)\nretry_delay = random.uniform(1, 2)\n", "weak-crypto")).toHaveLength(0);
    expect(py("import secrets\ntoken = secrets.token_urlsafe(32)\nsession_id = random.SystemRandom().choice(chars)\n", "weak-crypto")).toHaveLength(0);
  });

  it("ECB mode, DES and a low bcrypt cost; Django's MD5 hasher", () => {
    expect(py("cipher = AES.new(key, AES.MODE_ECB)\n", "weak-crypto")).toHaveLength(1);
    expect(py("cipher = DES.new(key, DES.MODE_CBC, iv)\n", "weak-crypto")).toHaveLength(1);
    expect(py("cipher = AES.new(key, AES.MODE_GCM, nonce=n)\n", "weak-crypto")).toHaveLength(0);
    expect(py("import bcrypt\nsalt = bcrypt.gensalt(rounds=4)\n", "weak-crypto")).toHaveLength(1);
    expect(py("import bcrypt\nsalt = bcrypt.gensalt(12)\n", "weak-crypto")).toHaveLength(0);
    expect(py('PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]\n', "weak-crypto", "/proj/settings.py")).toHaveLength(1);
    expect(py('PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]\n', "weak-crypto", "/proj/settings/test.py")).toHaveLength(0); // what test settings are for
  });
});

describe("insecure-cookie (Python)", () => {
  it("set_cookie for a login cookie without httponly=True", () => {
    expect(py('def v(r):\n    resp.set_cookie("session_token", t)\n', "insecure-cookie")).toHaveLength(1);
    expect(py('def v(r):\n    resp.set_cookie("access_token", t, httponly=False)\n', "insecure-cookie")).toHaveLength(1);
    expect(py('def v(r):\n    resp.set_cookie("access_token", t, httponly=True, secure=False)\n', "insecure-cookie")).toHaveLength(1);
    expect(py('def v(r):\n    resp.set_cookie("access_token", t, httponly=True, secure=True, samesite="Lax")\n', "insecure-cookie")).toHaveLength(0);
    expect(py('def v(r):\n    resp.set_cookie("theme", "dark")\n', "insecure-cookie")).toHaveLength(0);
  });

  it("Django / Flask settings with the cookie flags off; not in development settings", () => {
    expect(py("SESSION_COOKIE_SECURE = False\nCSRF_COOKIE_SECURE = False\nSESSION_COOKIE_HTTPONLY = False\n", "insecure-cookie", "/proj/settings.py")).toHaveLength(3);
    expect(py('app.config["SESSION_COOKIE_SECURE"] = False\n', "insecure-cookie")).toHaveLength(1);
    expect(py("SESSION_COOKIE_SECURE = False\n", "insecure-cookie", "/proj/settings/dev.py")).toHaveLength(0);
    expect(py("SESSION_COOKIE_SECURE = True\n", "insecure-cookie", "/proj/settings.py")).toHaveLength(0);
  });
});

describe("tls-verification (Python)", () => {
  it("verify=False on an HTTP client, an unverified context; jwt.decode(verify=False) is another rule", () => {
    expect(py('import requests\nr = requests.get(url, verify=False)\n', "tls-verification")).toHaveLength(1);
    expect(py('r = session.post(url, data=d, verify=False)\n', "tls-verification")).toHaveLength(1);
    expect(py("import httpx\nc = httpx.Client(verify=False)\n", "tls-verification")).toHaveLength(1);
    expect(py("import ssl\nctx = ssl._create_unverified_context()\n", "tls-verification")).toHaveLength(1);
    expect(py("ctx.verify_mode = ssl.CERT_NONE\nctx.check_hostname = False\n", "tls-verification")).toHaveLength(2);
    expect(py('claims = jwt.decode(token, verify=False)\n', "tls-verification")).toHaveLength(0);
    expect(py('r = requests.get(url, verify="/etc/ssl/ca.pem")\n', "tls-verification")).toHaveLength(0);
  });
});

describe("regex-injection (Python)", () => {
  it("a pattern from the request; re.escape makes it literal", () => {
    expect(py("@app.get('/s')\ndef s(q: str):\n    return re.search(q, text)\n", "regex-injection")).toHaveLength(1);
    expect(py("@app.get('/s')\ndef s(q: str):\n    return re.search(re.escape(q), text)\n", "regex-injection")).toHaveLength(0);
    expect(py("@app.get('/s')\ndef s(q: str):\n    return re.search(r'^[a-z]+$', q)\n", "regex-injection")).toHaveLength(0);
  });
});

describe("PHP", () => {
  it("weak-crypto: md5/sha1 over a password, rand() for a token, ECB, low cost", () => {
    expect(php("$h = md5($password);", "weak-crypto")).toHaveLength(1);
    expect(php("$h = sha1($_POST['password']);", "weak-crypto")).toHaveLength(1);
    expect(php("$h = hash('md5', $password);", "weak-crypto")).toHaveLength(1);
    expect(php("$etag = md5($content); $h = hash('sha256', $password);", "weak-crypto")).toHaveLength(0);
    expect(php("$reset_token = md5(uniqid(rand(), true));", "weak-crypto")).toHaveLength(1);
    expect(php("$token = bin2hex(random_bytes(32)); $color = rand(0, 255);", "weak-crypto")).toHaveLength(0);
    expect(php("$c = openssl_encrypt($data, 'aes-128-ecb', $key);", "weak-crypto")).toHaveLength(1);
    expect(php("$c = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);", "weak-crypto")).toHaveLength(0);
    expect(php("$h = password_hash($p, PASSWORD_BCRYPT, ['cost' => 4]);", "weak-crypto")).toHaveLength(1);
    expect(php("$h = password_hash($p, PASSWORD_BCRYPT, ['cost' => 12]);", "weak-crypto")).toHaveLength(0);
  });

  it("insecure-cookie: setcookie for a login cookie without httponly", () => {
    expect(php("setcookie('auth_token', $t);", "insecure-cookie")).toHaveLength(1);
    expect(php("setcookie('auth_token', $t, time() + 3600, '/');", "insecure-cookie")).toHaveLength(1);
    expect(php("setcookie('auth_token', $t, ['expires' => time() + 3600, 'httponly' => false]);", "insecure-cookie")).toHaveLength(1);
    expect(php("setcookie('auth_token', $t, ['httponly' => true, 'secure' => true]);", "insecure-cookie")).toHaveLength(0);
    expect(php("setcookie('auth_token', $t, 0, '/', '', true, true);", "insecure-cookie")).toHaveLength(0);
    expect(php("setcookie('theme', 'dark');", "insecure-cookie")).toHaveLength(0);
    expect(php("ini_set('session.cookie_httponly', 0);", "insecure-cookie")).toHaveLength(1);
  });

  it("tls-verification: cURL, Guzzle, stream contexts", () => {
    expect(php("curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);", "tls-verification")).toHaveLength(1);
    expect(php("curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);", "tls-verification")).toHaveLength(1);
    expect(php("$client = new Client(['verify' => false]);", "tls-verification")).toHaveLength(1);
    expect(php("$ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);", "tls-verification")).toHaveLength(2);
    expect(php("curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true); $c = new Client(['verify' => true]);", "tls-verification")).toHaveLength(0);
  });

  it("regex-injection: a pattern from the request; preg_quote makes it literal", () => {
    expect(php("$ok = preg_match($_GET['q'], $text);", "regex-injection")).toHaveLength(1);
    expect(php("$ok = preg_match('/' . preg_quote($_GET['q'], '/') . '/', $text);", "regex-injection")).toHaveLength(0);
    expect(php("$ok = preg_match('/^[a-z]+$/', $_GET['q']);", "regex-injection")).toHaveLength(0);
  });
});

describe("what the hardening rules must leave alone", () => {
  it("test-only branches and later entries of PASSWORD_HASHERS", () => {
    expect(py('import sys\nif "test" in sys.argv:\n    PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]\n', "weak-crypto", "/proj/settings.py")).toHaveLength(0);
    // only the first entry hashes new passwords; the weak ones after it exist to verify (and upgrade) old hashes
    expect(py('PASSWORD_HASHERS = ["django.contrib.auth.hashers.PBKDF2PasswordHasher", "django.contrib.auth.hashers.MD5PasswordHasher"]\n', "weak-crypto", "/proj/settings.py")).toHaveLength(0);
    expect(py('PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher", "django.contrib.auth.hashers.PBKDF2PasswordHasher"]\n', "weak-crypto", "/proj/settings.py")).toHaveLength(1);
  });

  it("PHP: a session key is judged by its own name, and time() is not a token", () => {
    expect(php("$_SESSION['last_visit'] = time(); $_SESSION['count'] = rand(1, 5);", "weak-crypto")).toHaveLength(0);
    const found = scanSource("<?php\n$_SESSION['session_token'] = md5(uniqid());\n", "/app/index.php").findings.filter((f) => f.ruleId === "weak-crypto");
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain("$_SESSION['session_token']");
  });

  it("a connection test that has to accept any certificate is reported with low confidence, not hidden", () => {
    const tester = scanSource("<?php\nfunction testConnection($host) { return stream_context_create(['ssl' => ['verify_peer' => false]]); }\n", "/app/Tester.php").findings.filter((f) => f.ruleId === "tls-verification");
    expect(tester).toHaveLength(1);
    expect(tester[0]?.confidence).toBe("low");
    const real = scanSource("<?php\nfunction fetchPrices($host) { return stream_context_create(['ssl' => ['verify_peer' => false]]); }\n", "/app/Prices.php").findings.filter((f) => f.ruleId === "tls-verification");
    expect(real[0]?.confidence).toBe("medium");
  });
});
