"""Optional real-browser APK workspace QA; every archive is an original synthetic fixture."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from io import BytesIO
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import threading
import traceback
from urllib.parse import urlsplit
import zipfile

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from asap.config import Config
from asap.server import make_server
from qa_browser import export_reviews, import_reviews, open_finding


@contextmanager
def dashboard():
    with tempfile.TemporaryDirectory(prefix='asap-workspace-browser-qa-') as directory:
        root = Path(directory)
        server = make_server(root, 0, Config(decompile=False))
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.01), daemon=True)
        thread.start()
        origin = f'http://127.0.0.1:{server.server_address[1]}'
        try:
            yield origin, root
        finally:
            server.shutdown()
            server.server_close()
            server.app.pool.shutdown(wait=True, cancel_futures=True)
            thread.join(timeout=5)


def apk_file(comment):
    """ZIP comments change binary identity while all source entries stay identical."""
    stream = BytesIO()
    fixture = ROOT / 'tests/fixtures/demo'
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for path in sorted(fixture.rglob('*')):
            if path.is_file():
                archive.writestr(zipfile.ZipInfo(path.relative_to(fixture).as_posix()), path.read_bytes())
        archive.writestr(zipfile.ZipInfo('classes.dex'), b'SYNTHETIC_NOT_A_VALID_DEX')
        archive.comment = comment.encode('ascii')
    return {'name': 'same-name.apk', 'mimeType': 'application/octet-stream', 'buffer': stream.getvalue()}


def fetch_json(context, url):
    response = context.request.get(url)
    assert response.status == 200, f'Local JSON response {response.status}: {url}'
    return response.json()


def upload(page, origin, apk):
    page.goto(origin, wait_until='load')
    with page.expect_response(lambda response: '/api/upload?' in response.url) as pending:
        page.locator('#apk-input').set_input_files(apk)
    response = pending.value
    assert response.status == 202, response.text()
    # The app immediately navigates after this XHR. Chrome can release that
    # response body before Playwright reads it, so observe the real destination.
    page.wait_for_url(re.compile(re.escape(origin) + r'/workspaces/[a-f0-9]{32}$'))
    workspace_id = urlsplit(page.url).path.rsplit('/', 1)[1]
    expect(page.locator('#workspace-jobs .job-card').first.locator('.badge')).to_have_text('완료', timeout=15000)
    expect(page.locator('#module-grid button')).to_have_count(7)
    detail = fetch_json(page.context, f'{origin}/api/workspaces/{workspace_id}')
    return {'id': detail['workspace']['latest_job']['id'], 'workspace_id': workspace_id}


def responsive(page, output, stem, checks):
    # Capture the normal top-of-page state after completing keyboard checks.
    page.locator('h1').click()
    for width in (375, 768, 1024, 1440):
        page.set_viewport_size({'width': width, 'height': 844 if width == 375 else 1080})
        page.evaluate('window.scrollTo(0, 0)')
        assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), f'{stem} overflows at {width}px'
        if stem == 'workspace' and width in (375, 1440):
            suffix = 'mobile' if width == 375 else 'desktop'
            page.screenshot(path=str(output / f'ui-workspace-{suffix}.png'), full_page=True)
        if stem == 'workspaces-home' and width == 1440:
            page.screenshot(path=str(output / 'ui-workspaces-home.png'), full_page=True)
    checks.append(f'{stem}: no document overflow at 375/768/1024/1440px and requested screenshots captured')


def run_checks(browser_path, output, checks, errors):
    first_apk, second_apk = apk_file('ASAP synthetic build A'), apk_file('ASAP synthetic build B')
    assert first_apk['buffer'] != second_apk['buffer']
    external_requests = []

    def observe(page):
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('console', lambda message: errors.append(message.text)
                if message.type == 'error' and not message.location.get('url', '').endswith('/favicon.ico')
                else None)

    def local_only(route):
        if urlsplit(route.request.url).hostname != '127.0.0.1':
            external_requests.append(route.request.url)
            route.abort()
        else:
            route.continue_()

    with dashboard() as (origin, directory), sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=browser_path, headless=True)
        version = browser.version
        try:
            context = browser.new_context(viewport={'width': 1440, 'height': 1080}, device_scale_factor=1, accept_downloads=True)
            context.route('**/*', local_only)
            context.on('page', observe)
            page = context.new_page()
            page.goto(origin, wait_until='load')
            expect(page.locator('#jobs .empty-state')).to_contain_text('첫 APK를 업로드하세요')
            page.keyboard.press('Tab')
            expect(page.locator('.skip-link')).to_be_focused()
            page.keyboard.press('Enter')
            page.locator('#workspace-search').focus()
            page.keyboard.press('Tab')
            expect(page.locator('#workspace-filter')).to_be_focused()
            checks.append('empty workspace home and keyboard navigation through skip link, search and archive filter')

            first = upload(page, origin, first_apk)
            first_id = first['workspace_id']
            first_url = f'{origin}/workspaces/{first_id}'
            expect(page.locator('#workspace-runs')).to_have_text('1')
            page.locator('#workspace-name').fill('Fixture A · APK review')
            page.locator('#workspace-note').fill('Synthetic APK A only.\nReview scope: original bundled fixture.')
            page.locator('#workspace-name').focus()
            page.keyboard.press('Tab')
            expect(page.locator('#workspace-note')).to_be_focused()
            page.keyboard.press('Tab')
            expect(page.locator('#save-workspace')).to_be_focused()
            page.keyboard.press('Enter')
            expect(page.locator('#workspace-feedback')).to_contain_text('워크스페이스 이름과 메모를 저장했습니다')
            expect(page.locator('#workspace-title')).to_have_text('Fixture A · APK review')
            page.reload(wait_until='load')
            expect(page.locator('#workspace-name')).to_have_value('Fixture A · APK review')
            expect(page.locator('#workspace-note')).to_have_value('Synthetic APK A only.\nReview scope: original bundled fixture.')
            checks.append('upload creates an APK workspace; keyboard save persists workspace name and multiline note after reload')

            duplicate = upload(page, origin, first_apk)
            assert duplicate['workspace_id'] == first_id and duplicate['id'] != first['id']
            expect(page.locator('#workspace-runs')).to_have_text('2')
            expect(page.locator('#workspace-jobs .job-card')).to_have_count(2)
            expect(page.locator('#workspace-name')).to_have_value('Fixture A · APK review')
            checks.append('identical-byte upload merges into its existing workspace and appends a separate scan without losing its name')

            second = upload(page, origin, second_apk)
            second_id = second['workspace_id']
            second_url = f'{origin}/workspaces/{second_id}'
            assert second_id != first_id
            expect(page.locator('#workspace-note')).to_have_value('')
            expect(page.locator('#workspace-jobs .job-card')).to_have_count(1)
            first_detail = fetch_json(context, f'{origin}/api/workspaces/{first_id}')
            second_detail = fetch_json(context, f'{origin}/api/workspaces/{second_id}')
            first_report = fetch_json(context, f'{origin}/reports/{duplicate["id"]}/report.json')
            second_report = fetch_json(context, f'{origin}/reports/{second["id"]}/report.json')
            assert first_detail['workspace']['sha256'] != second_detail['workspace']['sha256']
            assert first_detail['workspace']['package_name'] == second_detail['workspace']['package_name']
            assert first_report['scan']['source_set_sha256'] == second_report['scan']['source_set_sha256']
            assert {job['id'] for job in first_detail['jobs']} == {first['id'], duplicate['id']}
            assert {job['id'] for job in second_detail['jobs']} == {second['id']}
            checks.append('same filename/package/source hash with a different inert ZIP comment creates an isolated APK workspace and scoped history')

            page.goto(first_url, wait_until='load')
            expect(page.locator('#archive-workspace')).to_be_enabled()
            page.locator('#archive-workspace').click()
            expect(page.locator('#workspace-state')).to_have_text('보관됨')
            expect(page.locator('#rescan')).to_be_disabled()
            page.goto(origin, wait_until='load')
            expect(page.locator('#jobs .workspace-card')).to_have_count(1)
            expect(page.locator('#job-count')).to_have_text('1 / 2개 APK')
            page.locator('#workspace-filter').select_option('archived')
            expect(page.locator('#jobs .workspace-card')).to_have_count(1)
            expect(page.locator('#jobs .workspace-card-title')).to_have_text('Fixture A · APK review')
            page.locator('#jobs').get_by_role('link', name='워크스페이스 열기').click()
            expect(page.locator('#archive-workspace')).to_have_text('보관 해제')
            page.locator('#archive-workspace').click()
            expect(page.locator('#archive-workspace')).to_have_text('보관')
            expect(page.locator('#rescan')).to_be_enabled()
            with page.expect_response(lambda response: response.url.endswith(f'/api/workspaces/{first_id}/scan')) as pending:
                page.locator('#rescan').click()
            assert pending.value.status == 202
            rescan = pending.value.json()
            assert rescan['workspace_id'] == first_id and rescan['id'] not in {first['id'], duplicate['id']}
            expect(page.locator('#workspace-runs')).to_have_text('3')
            expect(page.locator('#workspace-jobs .job-card').first.locator('.badge')).to_have_text('완료', timeout=15000)
            expect(page.locator('#workspace-jobs .job-card')).to_have_count(3)
            assert len(list((directory / 'uploads').iterdir())) == 3
            checks.append('archive filter hides active-list entries; restore enables rescan and rescan appends history without another uploaded artifact')

            modules = fetch_json(context, f'{origin}/api/modules')
            assert len(modules) == 7
            for module in modules:
                button = page.locator(f'#module-grid button[data-category="{module["category"]}"]')
                button.focus()
                button.press('Enter')
                expect(page.locator('#module-title')).to_have_text(module['category'])
                expect(page.locator('#module-detail')).to_be_visible()
                expect(page.locator(f'#module-grid button[data-category="{module["category"]}"]')).to_be_focused()
                for selector in ('#module-questions li', '#module-safe li', '#module-changes li', '#module-limitations li'):
                    assert page.locator(selector).count() > 0
                if not page.locator('.module-rules').evaluate('node => node.open'):
                    page.locator('.module-rules summary').focus()
                    page.locator('.module-rules summary').press('Enter')
                references = page.locator('#module-references a')
                expect(references).to_have_count(len(module['references']))
                assert references.count() > 0
                for index, reference in enumerate(module['references']):
                    link = references.nth(index)
                    expect(link).to_be_visible()
                    expect(link).to_have_attribute('href', reference['url'])
                    expect(link).to_have_attribute('rel', 'noopener noreferrer')
                    assert reference['url'].startswith('https://')
                expect(page.locator('#module-report')).to_have_attribute('href', f'/reports/{rescan["id"]}/report.html#module={module["category"]}')
            checks.append('all seven module panels render review questions, safe patterns, changes, limitations and official reference links; keyboard activation retains focus')

            page.locator('#module-grid button[data-category="SQL_Injection"]').click()
            responsive(page, output, 'workspace', checks)
            page.locator('#module-finding-list a').filter(has_text='SQL001').click()
            expect(page.locator('#detail-dialog')).to_be_visible()
            expect(page.locator('#detail-rule')).to_contain_text('SQL001')
            page.locator('#triage-status').select_option('reviewing')
            page.locator('#triage-note').fill('Synthetic finding review belongs only to APK A.')
            page.locator('#save-triage').click()
            expect(page.locator('#triage-feedback')).to_contain_text('이 브라우저에 저장했습니다')
            page.locator('#close-dialog').click()
            expect(page.locator('#workspace-return')).to_be_visible()
            expect(page.locator('#workspace-return')).to_have_attribute('href', f'/workspaces/{first_id}')
            saved = export_reviews(page, directory)
            assert saved['apk_sha256'] == first_detail['workspace']['sha256']
            assert saved['source_set_sha256'] == first_report['scan']['source_set_sha256']
            first_key = f'asap-v3-review:apk:{saved["apk_sha256"]}:{saved["source_set_sha256"]}'
            assert page.evaluate('key => localStorage.getItem(key)', first_key) is not None
            page.locator('#workspace-return').click()
            page.wait_for_url(first_url)
            expect(page.locator('#workspace-name')).to_have_value('Fixture A · APK review')
            checks.append('module finding deep link opens its evidence dialog; APK-scoped review export includes binary hash; workspace return navigates correctly')

            page.goto(second_url, wait_until='load')
            expect(page.locator('#workspace-jobs .job-card')).to_have_count(1)
            page.locator('#workspace-jobs').get_by_role('link', name='리포트 열기').click()
            open_finding(page, 'SQL001')
            expect(page.locator('#triage-status')).to_have_value('unreviewed')
            expect(page.locator('#triage-note')).to_have_value('')
            page.locator('#close-dialog').click()
            before = export_reviews(page, directory)
            assert before['reviews'] == {}
            assert before['apk_sha256'] == second_detail['workspace']['sha256']
            import_reviews(page, saved, valid=False, error_text='APK')
            after = export_reviews(page, directory)
            assert after == before
            second_key = f'asap-v3-review:apk:{before["apk_sha256"]}:{before["source_set_sha256"]}'
            assert page.evaluate('key => localStorage.getItem(key)', second_key) is None
            checks.append('APK A notes stay absent in APK B despite matching source hashes; mismatched APK review import is rejected without storage mutation')

            page.goto(origin, wait_until='load')
            expect(page.locator('#jobs .workspace-card')).to_have_count(2)
            page.locator('#workspace-search').fill(first_detail['workspace']['sha256'][:20])
            expect(page.locator('#jobs .workspace-card')).to_have_count(1)
            expect(page.locator('#jobs .workspace-card-title')).to_have_text('Fixture A · APK review')
            page.locator('#workspace-search').fill('')
            expect(page.locator('#jobs .workspace-card')).to_have_count(2)
            responsive(page, output, 'workspaces-home', checks)
            checks.append('restored workspaces remain visible and SHA-256 search isolates the chosen APK')
            assert not external_requests, f'Unexpected external requests: {external_requests}'
            checks.append('all interactions remain on the temporary loopback server; decompilers and external requests are disabled')
            context.close()
        finally:
            browser.close()
    return version


def main():
    parser = argparse.ArgumentParser(description='Optional localhost APK workspace browser QA using only original synthetic archives.')
    parser.add_argument('--browser', default=shutil.which('chromium') or shutil.which('google-chrome'), help='Local browser executable; omit for Playwright Chromium')
    parser.add_argument('--output', type=Path, default=ROOT / 'results/qa', help='Directory for screenshots and check results')
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    checks, errors = [], []
    version = None
    try:
        version = run_checks(args.browser, output, checks, errors)
    except Exception as error:
        errors.append(f'{type(error).__name__}: {error}')
        traceback.print_exc()
    result = {
        'browser': 'Chromium', 'version': version,
        'mode': 'real local APK workspace navigation with deterministic synthetic ZIPs and decompilers disabled',
        'checks': checks, 'errors': errors, 'passed': not errors,
        'not_tested': ['Installable APK datasets, Android runtime behavior and external decompilers.',
                       'Other browser engines and operating systems not used for this run.'],
    }
    (output / 'workspace-browser-qa.json').write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
