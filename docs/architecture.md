# Architecture

Both the CLI and local dashboard use the same analysis engine:

```text
CLI / local dashboard
        |
Config + PreparedInput
        |
Sources + manifests + artifact inventory + diagnostics
        |
43 rules across 7 categories
        |
Context analysis → deduplication → fingerprints → baseline → suppressions
        |
ScanResult → JSON / SARIF / HTML
```

The engine can also be called from Python:

```python
from pathlib import Path
from asap.config import Config
from asap.engine import scan
from asap.reporting import write_reports

result = scan(Path("app.apk"), Config())
write_reports(result, Path("results/app"))
```

## Modules

Paths below are relative to `asap/`.

| Module | Responsibility |
|---|---|
| `cli.py`, `config.py` | Commands, configuration loading, and validation |
| `inputs.py` | Source collection, archive boundaries, decompiler processes, and temporary files |
| `axml.py` | Binary XML decoding |
| `manifest.py`, `xmlutil.py` | Manifest, resource, SDK, permission, and component parsing |
| `text.py` | Lexical method scopes, call arguments, receivers, and local assignments |
| `rules/registry.py` | Rule IDs, categories, severity, remediation, and references |
| `rules/analyze.py` | Source, manifest, secret, and Smali checks |
| `rules/entry_refinements.py`, `rules/data_refinements.py` | API argument, SDK, and receiver context analysis |
| `rules/firebase_paths.py`, `rules/firebase_local.py` | Firebase source path inventory and local Rules/exported JSON traversal |
| `guidance.py`, `guides/` | Module review guidance and references |
| `engine.py`, `model.py` | Scan orchestration, result models, fingerprints, baselines, and suppressions |
| `reporting.py` | Atomic report writing and HTML data encoding |
| `storage.py`, `server.py` | SQLite workspace metadata, upload handling, scan queue, and report routes |
| `web/` | Dashboard and report HTML, CSS, and JavaScript |

## Analysis pipeline

Source collection supports Java, Kotlin, XML, Smali, and selected text assets. It skips symlinks and configured exclusions. Vendor packages are excluded by default and can be included with `--include-vendor`.

For APK input, ASAP reads recoverable manifests, resources, and assets, and optionally invokes JADX or Apktool. APKS and XAPK inputs may contain up to 128 APKs, which are inspected individually. Native libraries are inventoried. Split selection, Android installation behavior, and signature verification are outside this pipeline.

Java/Kotlin analysis preserves text offsets while resolving calls and local assignments within a lexical method. Expression expansion is bounded by depth and size. Cross-method data flow, branch execution, and full type resolution are outside this model. Context analysis runs before findings are deduplicated and fingerprinted.

### Firebase inputs

The `Insecure_DataStorage` module processes Firebase RTDB references in source files, local Security Rules, and local exported JSON. Rules/data files can be collected from recognized input filenames or attached with `firebase_rules` and `firebase_data` configuration. Explicit attachments use canonical evidence paths and contribute their bytes to the source hash, so review state follows the full analysis input.

Source analysis inventories recognized Firebase hosts and SDK reference paths. Local JSON traversal records nested paths with a 4,096-node and 64-level bound. Rule analysis identifies unconditional `.read` and `.write` grants, including grants inherited from an ancestor. Dynamic rule conditions, invalid input, and traversal limits produce coverage diagnostics. Firebase's [rule inheritance semantics](https://firebase.google.com/docs/database/security/core-syntax) mean a child's `false` does not cancel an ancestor's grant; `.validate` constraints are separate from write authorization.

Export analysis reports path names and types without scalar values, and these data files bypass generic source/secret checks. The Firebase analyzers do not make network requests. See [input configuration](toolchain.md#firebase-local-inputs).

## Results

A `Finding` carries its rule, severity, confidence, evidence, remediation, references, fingerprint, and baseline/suppression state. Evidence uses relative paths and line numbers. For binary XML, line numbers refer to the decoded XML.

Fingerprints combine the rule, path, normalized evidence, and method or component context. They remain stable across simple line movement but can change after renaming, refactoring, or rule changes. Baselines are created explicitly with the CLI.

Coverage diagnostics identify unavailable or skipped analysis. Reports with diagnostics have `coverage.status=partial`; otherwise the status is `analyzed_with_documented_limits`. The JSON structure is defined in [report.schema.json](../schemas/report.schema.json).

## Dashboard state

Jobs progress through `uploading → queued → analyzing → completed | failed`. Unfinished jobs become `interrupted` after a server restart. One background worker processes scans, with up to eight pending jobs; individual source checks use the configured worker count.

SQLite stores APK workspace metadata and job state. Report files store analysis results. Browser localStorage stores finding review records separately, using the APK hash and source hash as their scope. False-positive and accepted-risk decisions require a note and do not modify the engine output. See [APK workspaces](workspaces.md) for the API and storage layout.
