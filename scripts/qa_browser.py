"""Optional real localhost browser QA using only bundled synthetic fixtures."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import threading
import traceback
import zipfile

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from asap.config import Config
from asap.engine import scan
from asap.reporting import render_html, sarif
from asap.server import make_server


@contextmanager
def local_dashboard(data, sarif_data):
    """Serve current UI assets and an existing synthetic report, with no tools."""
    with tempfile.TemporaryDirectory(prefix="asap-browser-qa-") as directory:
        workspace = Path(directory)
        server = make_server(workspace, 0, Config(decompile=False))
        job_id = "a" * 32
        report_dir = workspace / "reports" / job_id
        report_dir.mkdir(parents=True)
        (report_dir / "report.html").write_text(render_html(data), encoding="utf-8")
        (report_dir / "report.json").write_text(json.dumps(data), encoding="utf-8")
        (report_dir / "report.sarif").write_text(json.dumps(sarif_data), encoding="utf-8")
        server.app.store.create(job_id, "demo")
        server.app.store.update(job_id, "completed", active=data["summary"]["active"],
                                coverage=data["coverage"]["status"])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            yield origin, f"{origin}/reports/{job_id}/report.html", workspace
        finally:
            server.shutdown()
            server.server_close()
            server.app.pool.shutdown(wait=True, cancel_futures=True)
            thread.join(timeout=5)


def json_file(value, name="review.json"):
    return {"name": name, "mimeType": "application/json",
            "buffer": json.dumps(value, ensure_ascii=False).encode("utf-8")}


def export_reviews(page, workspace):
    with page.expect_download() as pending:
        page.locator("#export-review").click()
    download = pending.value
    assert download.suggested_filename == "asap-review-decisions.json"
    path = workspace / "downloaded-review.json"
    download.save_as(path)
    return json.loads(path.read_text(encoding="utf-8"))


def open_finding(page, rule="SQL001"):
    page.locator("#reset-filters").click()
    page.locator("#search").fill(rule)
    expect(page.locator("#findings-body tr")).to_have_count(1)
    page.locator("#findings-body tr").click()
    expect(page.locator("#detail-dialog")).to_be_visible()
    expect(page.locator("#detail-rule")).to_contain_text(rule)


def save_review(page, rule, status, note):
    open_finding(page, rule)
    page.locator("#triage-status").select_option(status)
    page.locator("#triage-note").fill(note)
    page.locator("#save-triage").click()
    expect(page.locator("#triage-feedback")).to_contain_text("이 브라우저에 저장했습니다")
    page.locator("#close-dialog").click()


def import_reviews(page, payload, valid=True, error_text=None):
    page.locator("#import-review-file").set_input_files(json_file(payload))
    if valid:
        expect(page.locator("#review-feedback")).to_be_visible()
        expect(page.locator("#review-feedback")).to_contain_text("개 검토 기록을 가져왔습니다")
        expect(page.locator("#error-banner")).to_be_hidden()
    else:
        expect(page.locator("#error-banner")).to_be_visible()
        if error_text:
            expect(page.locator("#error-banner")).to_contain_text(error_text)


def check_responsive(page, name, output, checks):
    for width in (375, 768, 1024, 1440):
        page.set_viewport_size({"width": width, "height": 844 if width == 375 else 1080})
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), (
            f"{name} document overflows at {width}px")
        if width in (375, 1440):
            suffix = "mobile" if width == 375 else "desktop"
            page.screenshot(path=str(output / f"ui-{name}-{suffix}.png"), full_page=True)
            if name == "report" and width == 1440:
                page.screenshot(path=str(output / "ui-report-overview.png"))
    checks.append(f"{name}: no document overflow at 375/768/1024/1440px; desktop/mobile screenshots")


def synthetic_apk():
    """An archive of source text, not an installable or executable Android app."""
    buffer = BytesIO()
    fixture = ROOT / "tests/fixtures/demo"
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for path in sorted(fixture.rglob("*")):
            if path.is_file():
                archive.writestr(path.relative_to(fixture).as_posix(), path.read_bytes())
        archive.writestr("classes.dex", "SYNTHETIC_NOT_A_VALID_DEX")
    return {"name": "synthetic-demo.apk", "mimeType": "application/octet-stream",
            "buffer": buffer.getvalue()}


def firebase_checks(browser, output, checks, errors):
    result = scan(ROOT / 'tests/fixtures/firebase', Config(decompile=False))
    with local_dashboard(result.to_dict(), sarif(result)) as (origin, report_url, _):
        context = browser.new_context(viewport={'width': 1440, 'height': 1080})
        requests = []
        def local_only(route):
            if route.request.url.startswith(origin + '/'):
                route.continue_()
            else:
                requests.append(route.request.url)
                route.abort()
        context.route('**/*', local_only)
        try:
            page = context.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(report_url, wait_until='load')
            open_finding(page, 'DS009')
            expect(page.locator('#firebase-path-panel')).to_be_visible()
            page.locator('#firebase-path-search').fill('/users/{dynamic}/profile')
            expect(page.locator('#firebase-path-rows tr')).to_have_count(1)
            expect(page.locator('#firebase-path-summary')).to_contain_text('asap-offline-fixture.firebaseio.com')
            page.locator('#close-dialog').click()
            checks.append('Firebase source inventory displays and filters SDK child chains with explicit dynamic segments')

            open_finding(page, 'DS012')
            page.locator('#firebase-path-search').fill('/users/fixtureUser/tags/0')
            expect(page.locator('#firebase-path-rows tr')).to_have_count(1)
            expect(page.locator('#firebase-path-rows')).to_contain_text('string')
            page.locator('#firebase-path-search').fill('')
            expected = next(f.properties['node_count'] for f in result.findings if f.rule_id == 'DS012')
            expect(page.locator('#firebase-path-rows tr')).to_have_count(expected)
            assert 'SYNTHETIC_PRIVATE_NAME_9261' not in page.content()
            for width in (375, 768, 1440):
                page.set_viewport_size({'width': width, 'height': 900})
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                assert page.locator('#firebase-path-panel').evaluate('node => node.scrollWidth <= node.clientWidth')
            page.screenshot(path=str(output/'ui-firebase-paths.png'))
            page.locator('#close-dialog').click()
            checks.append('Firebase export browser table includes nested object and array paths, omits scalar values, and fits mobile/desktop widths')

            open_finding(page, 'DS010')
            page.locator('#firebase-path-search').fill('/public/items')
            expect(page.locator('#firebase-path-rows')).to_contain_text('자식 false · 부모 허용 상속')
            page.locator('#close-dialog').click()
            open_finding(page, 'DS011')
            expect(page.locator('#detail-message')).to_contain_text('.validate')
            assert not requests, requests
            checks.append('Firebase Rules display inherited child grants and separate write validation without contacting any database')
        finally:
            context.close()


def run_checks(browser_path, output, checks, errors):
    result = scan(ROOT / "tests/fixtures/demo", Config(decompile=False))
    data = result.to_dict()
    expected_findings = len(data["findings"])
    assert expected_findings > 0 and len({finding["category"] for finding in data["findings"]}) == 7
    source_hash = data["scan"]["source_set_sha256"]
    storage_key = f"asap-v3-review:{source_hash}"
    fingerprint = next(f["fingerprint"] for f in data["findings"] if f["rule_id"] == "SQL001")
    other_fingerprint = next(f["fingerprint"] for f in data["findings"] if f["fingerprint"] != fingerprint)

    def observe(page):
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("console", lambda message: errors.append(message.text)
                if message.type == "error" and not message.location.get("url", "").endswith("/favicon.ico")
                else None)

    with local_dashboard(data, sarif(result)) as (origin, report_url, workspace), sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=browser_path, headless=True)
        version = browser.version
        try:
            context = browser.new_context(viewport={"width": 1440, "height": 1080},
                                          device_scale_factor=1, accept_downloads=True)
            context.on("page", observe)
            page = context.new_page()
            response = page.goto(report_url, wait_until="load")
            assert response.status == 200
            expect(page.locator("#metric-active")).to_have_text(str(expected_findings))
            expect(page.locator("#findings-body tr")).to_have_count(expected_findings)
            checks.append(f"real HTTP report navigation renders {expected_findings} synthetic observations and embedded script under CSP")
            check_responsive(page, "report", output, checks)

            page.locator("#severity").select_option("high")
            expect(page.locator("#findings-body tr")).to_have_count(sum(finding["severity"] == "high" and not finding["suppressed"] for finding in data["findings"]))
            open_finding(page)
            checks.append("severity/text filtering and evidence dialog")
            for status in ("false_positive", "accepted_risk"):
                page.locator("#triage-status").select_option(status)
                page.locator("#save-triage").click()
                expect(page.locator("#triage-feedback")).to_contain_text("근거가 필요합니다")
                assert page.evaluate("key => localStorage.getItem(key)", storage_key) is None
            checks.append("false-positive and accepted-risk decisions require a reason before mutation")

            page.locator("#triage-status").select_option("false_positive")
            page.locator("#triage-note").fill("Synthetic review: fixture verified by the reviewer.")
            page.locator("#save-triage").click()
            expect(page.locator("#triage-feedback")).to_contain_text("이 브라우저에 저장했습니다")
            page.locator("#close-dialog").click()
            page.locator("#reset-filters").click()
            page.locator("#review-status").select_option("false_positive")
            expect(page.locator("#findings-body tr")).to_have_count(1)
            expect(page.locator("#review-progress-text")).to_contain_text(f"1 / {expected_findings}")
            page.reload(wait_until="load")
            page.locator("#review-status").select_option("false_positive")
            expect(page.locator("#findings-body tr")).to_have_count(1)
            saved = export_reviews(page, workspace)
            assert saved["source_set_sha256"] == source_hash
            assert saved["reviews"][fingerprint]["status"] == "false_positive"
            checks.append("review-state filtering, progress, real localStorage persistence after reload, and JSON download")

            page.evaluate("key => localStorage.removeItem(key)", storage_key)
            page.reload(wait_until="load")
            import_reviews(page, saved)
            assert export_reviews(page, workspace) == saved
            page.locator("#review-status").select_option("false_positive")
            expect(page.locator("#findings-body tr")).to_have_count(1)
            checks.append("downloaded review JSON restores deleted browser decisions via the file input")

            candidate = {"status": "needs_fix", "note": "Synthetic candidate", "updated_at": "2099-01-01T00:00:00Z"}
            invalid_imports = []
            cross_source = deepcopy(saved)
            cross_source["source_set_sha256"] = "0" * 64
            invalid_imports.append(("different source", cross_source, "다른 소스"))
            unknown = {"schema_version": "3.0.0", "source_set_sha256": source_hash,
                       "reviews": {other_fingerprint: candidate, "unknown-fingerprint": candidate}}
            invalid_imports.append(("unknown fingerprint after a valid record", unknown, "현재 리포트에 없는"))
            bad_status = {"schema_version": "3.0.0", "source_set_sha256": source_hash,
                          "reviews": {other_fingerprint: candidate,
                                      fingerprint: {**candidate, "status": "invalid-status"}}}
            invalid_imports.append(("invalid status after a valid record", bad_status, "검토 상태"))
            for name, payload, error_text in invalid_imports:
                import_reviews(page, payload, valid=False, error_text=error_text)
                assert export_reviews(page, workspace) == saved, f"Non-atomic rejection: {name}"
                assert json.loads(page.evaluate("key => localStorage.getItem(key)", storage_key)) == saved["reviews"]
                checks.append(f"review import rejects {name} atomically in memory and storage")

            older = deepcopy(saved)
            older["reviews"][fingerprint] = {"status": "reviewing", "note": "Older synthetic decision",
                                              "updated_at": "2000-01-01T00:00:00Z"}
            import_reviews(page, older)
            assert export_reviews(page, workspace) == saved
            expect(page.locator("#review-feedback")).to_contain_text("기존 기록 1개 유지")
            checks.append("import preserves a newer local decision when an older record conflicts")

            page.locator("#category-nav button").filter(has_text="WebView").click()
            page.locator("#search").fill("no matching synthetic finding")
            page.locator("#severity").select_option("high")
            page.locator("#confidence").select_option("high")
            page.locator("#only-new").check()
            page.locator("#show-suppressed").check()
            page.locator("#import-file").set_input_files(json_file(data, "report.json"))
            expect(page.locator("#findings-body tr")).to_have_count(expected_findings)
            for selector in ("#search", "#severity", "#confidence", "#review-status"):
                expect(page.locator(selector)).to_have_value("")
            expect(page.locator("#only-new")).not_to_be_checked()
            expect(page.locator("#show-suppressed")).not_to_be_checked()
            expect(page.locator("#all-findings")).to_have_class("nav-item selected")
            expect(page.locator("#download-sarif")).to_be_hidden()
            page.locator("#search").fill("SQL001")
            page.locator("#reset-filters").click()
            expect(page.locator("#findings-body tr")).to_have_count(expected_findings)
            checks.append("report JSON import and reset button clear all filters and category selection")

            malformed_report = deepcopy(data)
            malformed_report["findings"][0]["evidence"] = None
            page.locator("#import-file").set_input_files(json_file(malformed_report, "malformed-report.json"))
            expect(page.locator("#error-banner")).to_contain_text("ASAP 3.0 JSON 형식이 아닙니다")
            expect(page.locator("#findings-body tr")).to_have_count(expected_findings)
            open_finding(page)
            expect(page.locator("#triage-status")).to_have_value("false_positive")
            page.locator("#close-dialog").click()
            assert export_reviews(page, workspace) == saved
            checks.append("malformed report JSON is rejected while the prior report, dialog, and review export remain usable")

            page.evaluate("key => localStorage.setItem(key, '{malformed-json')", storage_key)
            page.reload(wait_until="load")
            expect(page.locator("#findings-body tr")).to_have_count(expected_findings)
            expect(page.locator("#review-feedback")).to_contain_text("기존 검토 기록을 읽지 못했습니다")
            assert export_reviews(page, workspace)["reviews"] == {}
            checks.append("malformed localStorage leaves the report usable and displays recovery guidance")

            response = page.goto(origin, wait_until="load")
            assert response.status == 200
            expect(page.locator("#jobs .workspace-card")).to_have_count(1)
            expect(page.locator("#job-count")).to_have_text("1 / 1개 APK")
            assert page.locator(".home-main").evaluate("node => getComputedStyle(node).maxWidth") != "none"
            check_responsive(page, "home", output, checks)
            checks.append("actual home HTML, external CSS/JS, and live /api/workspaces render the migrated synthetic workspace")
            with page.expect_response(lambda response: "/api/upload?" in response.url) as upload_response:
                page.locator("#apk-input").set_input_files(synthetic_apk())
            assert upload_response.value.status == 202
            page.wait_for_url(re.compile(re.escape(origin) + r"/workspaces/[a-f0-9]{32}$"))
            uploaded = page.locator("#workspace-jobs .job-card").filter(has_text="synthetic-demo.apk")
            expect(uploaded.locator(".badge")).to_have_text("완료", timeout=15000)
            uploaded.get_by_role("link", name="리포트 열기").click()
            expect(page.locator("#scan-subtitle")).to_contain_text("synthetic-demo.apk")
            expect(page.locator("#findings-body tr")).not_to_have_count(0)
            checks.append("browser synthetic APK-text upload redirects into its APK workspace, completes, and opens its generated report; decompilers disabled")
            context.close()

            shared = browser.new_context(accept_downloads=True)
            shared.on("page", observe)
            first_tab, second_tab = shared.new_page(), shared.new_page()
            for tab in (first_tab, second_tab):
                tab.goto(report_url, wait_until="load")
                expect(tab.locator("#findings-body tr")).to_have_count(expected_findings)
            other_rule = next(f["rule_id"] for f in data["findings"] if f["fingerprint"] == other_fingerprint)
            save_review(first_tab, "SQL001", "reviewing", "Synthetic decision from the first tab.")
            save_review(second_tab, other_rule, "needs_fix", "Synthetic decision from the second tab.")
            second_tab.reload(wait_until="load")
            combined = export_reviews(second_tab, workspace)
            assert set(combined["reviews"]) == {fingerprint, other_fingerprint}
            assert combined["reviews"][fingerprint]["status"] == "reviewing"
            assert combined["reviews"][other_fingerprint]["status"] == "needs_fix"
            for status in ("reviewing", "needs_fix"):
                second_tab.locator("#review-status").select_option(status)
                expect(second_tab.locator("#findings-body tr")).to_have_count(1)
            checks.append("two same-source tabs opened before edits preserve both independent decisions after sequential saves and reload")

            subset = deepcopy(data)
            subset["findings"] = [f for f in subset["findings"] if f["fingerprint"] == fingerprint]
            subset["scan"]["input_name"] = "demo-subset"
            finding = subset["findings"][0]
            subset["summary"].update(total=1, active=1, suppressed=0, new=1)
            subset["summary"]["by_category"] = {name: int(name == finding["category"])
                                                  for name in subset["summary"]["by_category"]}
            subset["summary"]["by_severity"] = {name: int(name == finding["severity"])
                                                  for name in subset["summary"]["by_severity"]}
            second_tab.locator("#import-file").set_input_files(json_file(subset, "subset-report.json"))
            expect(second_tab.locator("#metric-active")).to_have_text("1")
            expect(second_tab.locator("#findings-body tr")).to_have_count(1)
            expect(second_tab.locator("#review-progress-text")).to_contain_text("1 / 1")
            save_review(second_tab, "SQL001", "accepted_risk", "Synthetic scoped review with a documented reason.")
            subset_export = export_reviews(second_tab, workspace)
            assert set(subset_export["reviews"]) == {fingerprint}
            assert subset_export["reviews"][fingerprint]["status"] == "accepted_risk"
            stored = json.loads(second_tab.evaluate("key => localStorage.getItem(key)", storage_key))
            assert set(stored) == {fingerprint, other_fingerprint}
            assert stored[other_fingerprint] == combined["reviews"][other_fingerprint]
            second_tab.reload(wait_until="load")
            expect(second_tab.locator("#metric-active")).to_have_text(str(expected_findings))
            restored = export_reviews(second_tab, workspace)
            assert restored["reviews"] == stored
            for status in ("accepted_risk", "needs_fix"):
                second_tab.locator("#review-status").select_option(status)
                expect(second_tab.locator("#findings-body tr")).to_have_count(1)
            checks.append("same-source subset saves retain out-of-scope stored decisions, export only current findings, and restore all on full-report reload")
            shared.close()

            blocked = browser.new_context(accept_downloads=True)
            blocked.on("page", observe)
            blocked.add_init_script("""
                for (const method of ['getItem', 'setItem']) {
                    Object.defineProperty(Storage.prototype, method, {
                        configurable: true,
                        value() { throw new DOMException('Synthetic storage restriction', 'SecurityError'); }
                    });
                }
            """)
            page = blocked.new_page()
            page.goto(report_url, wait_until="load")
            expect(page.locator("#findings-body tr")).to_have_count(expected_findings)
            open_finding(page)
            page.locator("#triage-status").select_option("reviewing")
            page.locator("#triage-note").fill("Keep this synthetic review in memory for export.")
            page.locator("#save-triage").click()
            expect(page.locator("#triage-feedback")).to_contain_text("저장소 접근이 제한됐습니다")
            page.locator("#close-dialog").click()
            page.locator("#reset-filters").click()
            page.locator("#review-status").select_option("reviewing")
            expect(page.locator("#findings-body tr")).to_have_count(1)
            expect(page.locator("#review-progress-text")).to_contain_text(f"1 / {expected_findings}")
            assert export_reviews(page, workspace)["reviews"][fingerprint]["status"] == "reviewing"
            checks.append("blocked storage read/write still permits in-memory review updates, filtering, progress, and export")
            blocked.close()
            firebase_checks(browser, output, checks, errors)
        finally:
            browser.close()
    return version


def main():
    parser = argparse.ArgumentParser(description="Optional real localhost UI QA; requires Playwright and local Chromium/Chrome.")
    parser.add_argument("--browser", default=shutil.which("chromium") or shutil.which("google-chrome"),
                        help="Browser executable; omit to use Playwright's installed Chromium")
    parser.add_argument("--output", type=Path, default=ROOT / "results/qa",
                        help="Directory for screenshots and check results")
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    checks, errors = [], []
    version = None
    try:
        version = run_checks(args.browser, output, checks, errors)
    except Exception as error:
        errors.append(f"{type(error).__name__}: {error}")
        traceback.print_exc()
    result = {
        "browser": "Chromium", "version": version,
        "mode": "real localhost navigation against ASAP make_server in a temporary workspace",
        "checks": checks, "errors": errors, "passed": not errors,
        "not_tested": [
            "Real APK datasets, Android execution, and external JADX/Apktool decompilation.",
            "file:// browser navigation, other browser engines, and operating systems not used for this run.",
        ],
    }
    (output / "browser-qa.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
