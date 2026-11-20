# Pocket Notes (security practice app)

Pocket Notes is a small notes web app and JSON API, with users, login, notes, sharing, a profile page and an admin page, built on Node.js 24, Express 5 and SQLite through the built-in `node:sqlite` module. It is the companion code for the Sypher course "Security Testing Basics". The repository holds two copies of the app: `vulnerable/`, which is insecure on purpose so you can find, prove and fix one family of flaws per lesson, and `fixed/`, the same app with every flaw fixed. Around them are 23 security regression tests, the attack helper scripts from the lessons, three custom Semgrep rules, a ZAP scan plan and rule configuration, and an example GitHub Actions workflow.

## Read this first: safety

- The app in `vulnerable/` is **deliberately insecure**. It has SQL injection, cross-site scripting, broken access control, a password reset backdoor, guessable sessions and more. Treat it like a practice target, not like software.
- Both apps bind to **127.0.0.1 only** (`listen(port, '127.0.0.1')` in `src/server.js`), so only programs on your own computer can reach them. Do not change that binding, do not open the ports in a firewall, do not forward them from a router, and do not run the apps inside a container or virtual machine that publishes their ports to a network.
- **Never deploy the vulnerable app** to a server, a cloud account, a shared test environment or any machine other than your own.
- Point the scanners (ZAP, the attack scripts in `scripts/`, curl) **only at the practice apps on your own machine**. Testing a system you do not own, without written permission, is illegal in most countries, and an active scan changes and deletes data.
- All passwords, password hashes, tokens and API keys in this repository are fake practice data.

If you ever see either app listening on `0.0.0.0` (all network interfaces), stop it.

## Set up your computer

You need Git (on Windows it also gives you Git Bash, the shell every command in this README is written for), Node.js 24, Docker, Python 3.10 or newer, curl and a browser (Chrome, Edge or Firefox). Node.js and Git are enough to run the apps and the tests; Docker is for the ZAP scans and Python for Semgrep.

On Windows, run every command below in **Git Bash**, not in PowerShell or Command Prompt. The course uses bash syntax such as `$(...)`, `grep` and `export`.

### Git

| System | Install |
|---|---|
| Windows | `winget install --id Git.Git -e`, or the installer from the Git downloads page (https://git-scm.com/downloads). It installs Git Bash and curl. |
| macOS | `xcode-select --install` (Apple's command line tools include Git), or `brew install git` |
| Debian or Ubuntu | `sudo apt install -y git` |
| Fedora or RHEL | `sudo dnf install -y git` |

Check it:

```bash
git --version
```

It prints a line such as `git version 2.51.0`. Any recent version works.

### Node.js 24 LTS

Installing Node.js also installs npm. Use Node.js 24 or newer: the app uses `node:sqlite`, which older lines do not have.

| System | Install |
|---|---|
| Windows | `winget install OpenJS.NodeJS.LTS`, or the installer from the Node.js downloads page (https://nodejs.org/en/download) |
| macOS | `brew install node@24` (Homebrew prints a line to add `node@24` to your `PATH`; add it and open a new terminal), or the installer from the same downloads page |
| Linux | Use a version manager, because the `nodejs` package in many distributions is too old. With nvm (https://github.com/nvm-sh/nvm): `curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh \| bash`, open a new terminal, then `nvm install 24` |

fnm (https://github.com/Schniz/fnm) works the same way (`fnm install 24`) on all three systems if you prefer to switch Node.js versions per project.

Open a new terminal and check:

```bash
node --version
npm --version
```

You see version numbers like these (the course was checked with exactly these):

```text
v24.19.0
11.17.0
```

The first line must start with `v24` or higher.

### Docker

Docker runs ZAP, the dynamic scanner, in a container. You need it for the scanning steps only.

| System | Install |
|---|---|
| Windows | Docker Desktop: `winget install -e --id Docker.DockerDesktop`, or the installer from the Docker Desktop page (https://docs.docker.com/desktop/). Keep the WSL 2 option selected, then start Docker Desktop from the Start menu. |
| macOS | Docker Desktop: `brew install --cask docker`, or the installer from the same page. Start Docker from Applications. |
| Linux | Docker Engine: follow the `apt` or `dnf` repository steps on the Docker Engine install page (https://docs.docker.com/engine/install/), or use the convenience script: `curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh`. Then run `sudo usermod -aG docker $USER` and open a new shell. |

Check it:

```bash
docker version --format 'Docker Engine {{.Server.Version}}'
```

It prints a line such as `Docker Engine 28.0.1`. If it prints an error about connecting to the Docker daemon, Docker is installed but not running: start Docker Desktop, or run `sudo systemctl start docker` on Linux.

Then download the ZAP image (about 2.4 GB) and check that it holds ZAP 2.17 and the packaged scan scripts:

```bash
docker pull zaproxy/zap-stable
docker run --rm zaproxy/zap-stable sh -c 'ls /zap | grep -E "jar|py$"'
```

```text
zap-2.17.0.jar
zap-api-scan.py
zap-baseline.py
zap-full-scan.py
zap_common.py
```

A newer image may show a newer jar version; that is fine.

### Python 3.10 or newer

Python runs Semgrep, the static analyser, in a virtual environment. You need it for the static analysis steps only.

| System | Install |
|---|---|
| Windows | `winget install Python.Python.3.14`, or the installer from the Python downloads page (https://www.python.org/downloads/). If you use the installer, tick "Add python.exe to PATH". |
| macOS | `brew install python@3.14` |
| Debian or Ubuntu | `sudo apt install -y python3 python3-venv` |
| Fedora or RHEL | `sudo dnf install -y python3` |

Check it (the command is `python` on Windows and `python3` on macOS and Linux):

```bash
python --version
```

It prints a line such as `Python 3.14.3`. The version must be 3.10 or higher.

### curl and a browser

curl sends the hand-made HTTP requests in the lessons. Git for Windows includes it, macOS ships with it, and on Linux you install it with `sudo apt install -y curl` or `sudo dnf install -y curl`. Check it with `curl --version`, which prints a first line such as `curl 8.1.2 ...`. Any current Chrome, Edge or Firefox works for the browser steps.

### Get the code

Clone the repository (or download it as a ZIP from GitHub and unpack it) into a folder of its own, because the Semgrep virtual environment goes next to it:

```bash
mkdir security-testing && cd security-testing
git clone <repository URL> pocket-notes-security
```

You end up with `security-testing/pocket-notes-security/`. Every command below runs from `pocket-notes-security/` or one of its subfolders, as each step says.

### Install Semgrep

From the folder that contains `pocket-notes-security` (here `security-testing/`), create a virtual environment named `.venv` and install Semgrep into it. The lesson commands and `scripts/security-check.sh` expect it in exactly that place.

On Windows (Git Bash):

```bash
python -m venv .venv
.venv/Scripts/python -m pip install semgrep
export PYTHONUTF8=1
.venv/Scripts/semgrep --version
```

On macOS and Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install semgrep
.venv/bin/semgrep --version
```

The last command prints a version such as `1.183.0`. On Windows, set `PYTHONUTF8=1` in every new Git Bash window before you run Semgrep (`export PYTHONUTF8=1`), because its output contains characters the default Windows code page cannot print. Every Semgrep command in this README passes `--metrics=off` and never logs in, so no code and no usage data leave your computer.

## Run the app

The course uses these addresses. All of them are on your own machine:

| What | Address |
|---|---|
| Vulnerable app | `http://127.0.0.1:18401` (also `http://localhost:18401`) |
| Fixed app | `http://localhost:18402` |
| Pretend attacker site (lesson 9, `node scripts/attacker-site.mjs`) | `http://127.0.0.1:18490` and `http://localhost:18490` |

1. Install and start the vulnerable app, from `pocket-notes-security`:

   ```bash
   cd vulnerable
   npm install
   npm start
   ```

   `npm install` ends with `1 high severity vulnerability`. That is the old lodash 4.17.20, kept on purpose for lesson 12; do not run `npm audit fix`. `npm start` prints:

   ```text
   > pocket-notes-vulnerable@1.0.0 start
   > node src/server.js

   Pocket Notes (VULNERABLE practice app) on http://127.0.0.1:18401
   Never expose this app to a network.
   ```

   Leave it running in this terminal.

2. In a second terminal, configure, install and start the fixed app, from `pocket-notes-security`:

   ```bash
   cd fixed
   cp .env.example .env
   ```

   Open `fixed/.env` and set `MAIL_API_KEY` to any test value, for example `pn_test_fake_key_for_local_runs_only`. The app refuses to start without it, and `.env` is in `.gitignore`, so it is never committed. Then:

   ```bash
   npm install
   npm start
   ```

   `npm install` ends with `found 0 vulnerabilities`, and `npm start` prints:

   ```text
   > pocket-notes-fixed@1.0.0 start
   > node --env-file=.env src/server.js

   Pocket Notes (fixed) on http://localhost:18402
   ```

3. In a third terminal, check that both apps answer. A visitor who is not logged in is sent to the login page:

   ```bash
   curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://127.0.0.1:18401/
   curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://localhost:18402/
   ```

   ```text
   302 http://127.0.0.1:18401/login
   302 http://localhost:18402/login
   ```

4. Check that both apps listen on the loopback address only:

   ```bash
   netstat -an | grep -E '1840[12].*LISTEN'
   ```

   On Windows the output looks like this (macOS and Linux show `127.0.0.1.18401` or `127.0.0.1:18401` in a slightly different layout):

   ```text
     TCP    127.0.0.1:18401        0.0.0.0:0              LISTENING
     TCP    127.0.0.1:18402        0.0.0.0:0              LISTENING
   ```

5. Open `http://localhost:18401` in your browser and log in as `alice@pocket.test` with the password `alice-likes-long-passwords`. You see Alice's two notes.

The three practice accounts are `admin@pocket.test` / `Admin-Pocket-2026` (admin), `alice@pocket.test` / `alice-likes-long-passwords` and `bob@pocket.test` / `letmein`. The database lives in memory and is filled with the same seed data on every start, so stopping an app with Ctrl+C and running `npm start` again resets it.

## Running the tests

### The security regression tests

Each app has the same file, `test/security.test.js`, with 23 tests written with `node:test` and supertest. The tests build their own app in memory, so you do not need to start a server. Run them in `vulnerable/` and then in `fixed/` (after `npm install` in each):

```bash
node --test 2>&1 | grep -E '^ℹ (tests|pass|fail)'
```

In `vulnerable/`:

```text
ℹ tests 23
ℹ pass 0
ℹ fail 23
```

In `fixed/`:

```text
ℹ tests 23
ℹ pass 23
ℹ fail 0
```

Every test name starts with the lesson that adds it (`L04` to `L15`), so you can run one lesson's tests, for example `node --test --test-name-pattern=L06` (4 tests). To write a JUnit report the way the CI workflow does (lesson 16):

```bash
node --test --test-reporter=spec --test-reporter-destination=stdout --test-reporter=junit --test-reporter-destination=junit.xml
```

### Static analysis with Semgrep (lesson 13)

With the virtual environment from "Install Semgrep", in `vulnerable/` (on macOS and Linux replace `.venv/Scripts/semgrep` with `.venv/bin/semgrep`):

```bash
../../.venv/Scripts/semgrep scan --config ../semgrep/pocket-notes.yaml --metrics=off src/
```

The custom rules report four findings in `vulnerable/`: the password written to the log (`src/app.js` line 58), the SQL built with a template literal (`src/app.js` line 118) and the two secrets in `src/config.js` (lines 6 and 7). The same command in `fixed/` reports none. To test the rules themselves against their annotated test files, run this in `semgrep/`:

```bash
../../.venv/Scripts/semgrep --test --metrics=off .
```

```text
4/4: ✓ All tests passed
No tests for fixes found.
```

### Dynamic scanning with ZAP (lesson 14)

Start the app you want to scan first (step 1 or 2 of "Run the app"). The commands run from `pocket-notes-security`; the `zap` folder is mounted into the container, so reports land in `zap/reports/`.

On Windows in Git Bash, `MSYS_NO_PATHCONV=1` stops the shell rewriting the container path and `pwd -W` gives a Windows-style path for the volume:

```bash
export MSYS_NO_PATHCONV=1
mkdir -p zap/reports
docker run --rm --name sec-zap -v "$(pwd -W)/zap:/zap/wrk/:rw" -t zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:18401 -z -silent \
  -r reports/baseline-vulnerable.html -J reports/baseline-vulnerable.json
```

On macOS with Docker Desktop, use the same command with `$(pwd)` instead of `$(pwd -W)` and without the `export` line. On Linux with Docker Engine, `host.docker.internal` does not exist; add `--network host` and aim at the loopback address:

```bash
mkdir -p zap/reports
docker run --rm --name sec-zap --network host -v "$(pwd)/zap:/zap/wrk/:rw" -t zaproxy/zap-stable \
  zap-baseline.py -t http://127.0.0.1:18401 -z -silent \
  -r reports/baseline-vulnerable.html -J reports/baseline-vulnerable.json
```

The baseline scan takes about a minute. It spiders the app and checks every response without attacking, then prints one line per alert and a summary. For the vulnerable app the summary is:

```text
FAIL-NEW: 0	FAIL-INPROG: 0	WARN-NEW: 9	WARN-INPROG: 0	INFO: 0	IGNORE: 0	PASS: 53
```

and the exit code is 2 (warnings only). The nine warnings are the missing security headers, the session cookie without `HttpOnly` or `SameSite`, `X-Powered-By`, and forms without anti-CSRF tokens. Against the fixed app with the project's rule configuration (`-t http://host.docker.internal:18402 -z -silent -c baseline-fixed.conf -r reports/baseline-fixed-conf.html`) the scan exits 0.

The `-silent` option stops ZAP itself from making requests you did not ask for, such as update checks. Lesson 14 also runs an authenticated full scan and the Automation Framework plan in `zap/plan-fixed.yaml`; both are active scans that send attack requests and change the app's data, so run them only against a freshly started copy on your own machine.

### All automated checks at once (lessons 16 and 17)

`scripts/security-check.sh` runs the security tests, Semgrep with the custom rules and `npm audit` with the production gate, the same way CI does. Run it from `pocket-notes-security` after `npm install` in both apps (it finds Semgrep in `../.venv`; set `SEMGREP=/path/to/semgrep` to use another one):

```bash
bash scripts/security-check.sh vulnerable; echo "exit code: $?"
```

```text
FAIL  security tests (node --test)
FAIL  static analysis (semgrep --error)
FAIL  dependencies (npm audit --omit=dev --audit-level=high)
exit code: 1
```

```bash
bash scripts/security-check.sh fixed; echo "exit code: $?"
```

```text
PASS  security tests (node --test)
PASS  static analysis (semgrep --error)
PASS  dependencies (npm audit --omit=dev --audit-level=high)
exit code: 0
```

### The CI workflow (lesson 16)

`.github/workflows/security.yml` runs on every pull request and every push to `main`, against the **fixed** app only: `npm ci --ignore-scripts`, the 23 tests with a JUnit report, `npm audit --omit=dev --audit-level=high`, Semgrep with `semgrep/pocket-notes.yaml`, then it starts the app on the runner's own loopback address and runs a ZAP baseline scan against `http://127.0.0.1:18402` with `zap/baseline-fixed.conf`. It never scans any other host; the only outside traffic is downloading the actions, Semgrep and the ZAP image. The job token has `contents: read` only.

The workflow reads the app's mail key from a repository secret named `MAIL_API_KEY_TEST`. After you push the repository to GitHub, add that secret (Settings, Secrets and variables, Actions) with any fake value such as `pn_test_fake_key_for_local_runs_only`; without it the fixed app does not start and the ZAP step fails. The action versions (`@v7`) are the ones the course was written with; check them when you copy the file.

## Project layout

```text
pocket-notes-security/
  vulnerable/                 the deliberately insecure app (port 18401); each flaw has a FLAW comment
    package.json              express 5.3.0, lodash 4.17.20 (old on purpose), supertest 7.3.1
    src/server.js             starts the app on 127.0.0.1 only
    src/app.js                routes, sessions, login, notes, search, profile, admin, JSON API
    src/db.js                 in-memory SQLite with three users, four notes and one share
    src/config.js             settings, with two (fake) secrets written into the code
    src/views.js              HTML pages built with unescaped template strings
    test/security.test.js     the 23 security regression tests
  fixed/                      the same app with every flaw fixed (port 18402); fixes have FIX comments
    .env.example              copy to .env and set MAIL_API_KEY
    package.json              adds helmet and express-rate-limit, drops lodash
    public/                   the notes page script (DOM XSS fix) and stylesheet, served from /static
    src/, test/               as in vulnerable/
  scripts/
    find-accounts.mjs         account enumeration through the login messages (lesson 4)
    guess-password.mjs        tries common passwords against one account (lesson 4)
    find-sessions.mjs         guesses session ids (lesson 5)
    attacker-site.mjs         a pretend attacker site on port 18490 for CSRF and CORS (lesson 9)
    crack-sha256.mjs          looks a leaked unsalted hash up in a word list (lesson 11)
    login-flood.mjs           many failed logins for different emails (lesson 15)
    security-check.sh         tests, Semgrep and npm audit in one run (lesson 16)
  semgrep/
    pocket-notes.yaml         three custom rules: SQL from template literals, hard-coded secrets, passwords in logs
    pocket-notes.js           annotated test file for those rules (semgrep --test)
    taint-demo.yaml, .js      the taint-mode example rule and its test file
  zap/
    baseline-fixed.conf       baseline rule configuration that makes the scan a gate for the fixed app
    plan-fixed.yaml           Automation Framework plan for an authenticated scan of the fixed app
  .github/workflows/security.yml   the example CI pipeline from lesson 16
```

## Troubleshooting

- **`Error: listen EADDRINUSE` on 18401 or 18402.** Another copy of the app (or another program) already uses the port. Find it with `netstat -ano | grep 18401` on Windows or `lsof -i :18401` on macOS and Linux and stop it. Or start the vulnerable app on another port with `PORT=18411 npm start`; for the fixed app change `PORT` in `fixed/.env` (and `ALLOWED_ORIGINS` to match).
- **The fixed app stops with `.env: not found` or `Missing environment variable MAIL_API_KEY`.** You skipped step 2 of "Run the app": copy `fixed/.env.example` to `fixed/.env` and give `MAIL_API_KEY` a value.
- **ZAP cannot reach the app, or the report shows almost no URLs.** The app is not running, or the container cannot reach it. Check the app with the curl command from step 3. On Linux, use `--network host` and `http://127.0.0.1:18401`, because `host.docker.internal` only exists with Docker Desktop. If Docker itself answers with an error about the Docker daemon, start Docker Desktop or `sudo systemctl start docker`.
- **On Windows the ZAP command fails with a path error, or no reports appear in `zap/reports/`.** Git Bash rewrote the container path `/zap/wrk/` into a Windows path. Run `export MSYS_NO_PATHCONV=1` first and use `$(pwd -W)` in the volume, as shown above.
- **Semgrep fails on Windows with `UnicodeEncodeError`, or `security-check.sh` says the static analysis failed in `fixed/`.** Run `export PYTHONUTF8=1` in that Git Bash window, and make sure the virtual environment is at `../.venv` next to `pocket-notes-security` (or set `SEMGREP` to the full path of the `semgrep` program).

## License

Copyright (C) 2026 SypherNext

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). You may
use, study and change it. If you share a modified version, or run one as a website or service
that other people use, you must make your full modified source code available under the same
license. See [LICENSE](LICENSE) for the full terms.
