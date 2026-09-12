# Development checks

Run these commands from the repository root with Python 3.11 or later.

## Unit and integration tests

```bash
python3 -m unittest discover -s tests -v
```

The suite covers analysis rules, Java/Kotlin context handling, manifest and binary XML parsing, archive limits, report generation, baselines, suppressions, CLI behavior, and the local workspace API. Firebase checks use synthetic source references, local Rules documents, and exported JSON to cover child paths, inherited grants, malformed input, traversal limits, and omission of scalar data values. The suite uses synthetic sources and temporary files.

## Sample analysis

```bash
python3 -m asap scan tests/fixtures/demo -o results/demo --legacy-json --strict
```

Open `results/demo/report.html` to inspect the generated report. The output directory also contains JSON and SARIF reports, plus compatibility JSON when `--legacy-json` is used. `--strict` returns exit code 2 if coverage diagnostics are present.

The fixture directory contains static source examples rather than a buildable Android app. APK wrappers used by tests are synthetic archives; they do not exercise real DEX decompilation.

## Distribution check

```bash
python3 scripts/check_distribution.py
```

This checks the required project files, rule and category contracts, example configurations, and generated report structure using the standard library.

## Browser checks

Install Playwright in a development environment and provide a local Chromium-based browser executable:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install playwright
.venv/bin/python scripts/qa_browser.py --browser '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
.venv/bin/python scripts/qa_workspaces.py --browser '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
```

Replace the Python and browser paths for your platform. Alternatively, install Playwright Chromium with `.venv/bin/python -m playwright install chromium` and omit `--browser` when no system browser is detected.

The scripts start a temporary local server and write JSON results and screenshots under `results/qa/`. They exercise report navigation, review persistence and imports, APK identity and history, workspace editing and archiving, module guidance, keyboard navigation, and responsive layouts. Decompilers are disabled for these synthetic browser fixtures.

## Package build

```bash
.venv/bin/python -m pip install build
.venv/bin/python -m build --wheel
```

To test the package independently of the checkout, install the wheel in a separate virtual environment and run `asap --help` and a fixture scan from another directory. APK decompiler integration can be checked separately with configured JADX/Apktool installations and a local test APK.
