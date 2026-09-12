# APK workspaces

ASAP groups uploads by the SHA-256 hash of the original APK, APKS, or XAPK file. Uploading identical bytes adds a scan to the same workspace. Files with different bytes get separate workspaces, including files with the same name or package name.

## Start the dashboard

```bash
python3 -m asap web --workspace .asap-workspace --port 8765
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). To configure decompilers and analysis options, add `--config my-config.json`; see [Tool setup](toolchain.md).

## Manage an APK

1. Upload a file or open a workspace from the home page.
2. Set its display name and notes. The workspace shows the original hash, package information, SDK information, and scan history.
3. Select a module to see findings, review guidance, and references from its latest completed scan.
4. Open a finding to inspect the evidence and save a review status or note.
5. Use **Reanalyze** to scan the retained upload with the server's current configuration.

Module summaries use the latest completed scan while another scan is running. Open individual reports in the history to inspect earlier results. A module that was not selected or has no completed scan is shown separately from a module with no findings.

Archiving hides a workspace from the active list while keeping its uploads and reports. Use the archived filter to restore it. Restore an archived workspace before reanalyzing it. If the retained upload is missing or has changed, upload the same file again to restore the input.

## Stored data

The directory passed to `--workspace` contains:

| Location | Contents |
|---|---|
| `asap.sqlite3` | Workspace names, notes, archive state, package metadata, and scan history |
| `uploads/` | Retained APK, APKS, and XAPK uploads |
| `reports/{job_id}/` | HTML, JSON, and SARIF reports for each completed scan |

Workspace notes are available to browsers connected to the same server. Finding review records are stored in the browser's localStorage, scoped by the APK hash and analysis source hash. Use the report's JSON export and import controls to move those records between browsers. Imports for another APK or source set are rejected. CLI source reports use the source hash to scope review records.

Stop the server before backing up or removing workspace files. Back up the complete workspace directory to retain uploads and reports; export browser review records separately. Archiving does not delete data, and stored uploads do not expire automatically.

## Local API

| Request | Purpose |
|---|---|
| `GET /api/workspaces` | List workspaces, recent status, and scan counts |
| `GET /api/workspaces/{id}` | Read APK metadata and scan history |
| `POST /api/workspaces/{id}` | Update `display_name`, `note`, or `archived` |
| `POST /api/workspaces/{id}/scan` | Reanalyze the retained APK |
| `GET /api/modules` | Read module rules, review guidance, and references |

Mutation requests require the dashboard's Host, Origin, and CSRF checks. JSON bodies are limited to 16 KiB, names to 200 characters, and notes to 4,000 characters. Uploads are limited to 512 MiB. The server accepts up to eight pending jobs and runs one scan at a time. It binds to `127.0.0.1` for single-user local use.
