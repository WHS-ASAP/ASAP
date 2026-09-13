# Tool setup

## Python

ASAP requires Python 3.11 or later. Run it directly from the repository with no additional Python runtime packages:

```bash
python3 -m asap --help
python3 -m asap web
```

To install the `asap` command in a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/asap --help
```

On Windows, use `.venv\Scripts\python.exe` and `.venv\Scripts\asap.exe`.

## JADX

Install JADX from its [official releases](https://github.com/skylot/jadx/releases) and follow the Java requirements for the selected release. Keep the extracted distribution together, including its `bin/` and `lib/` directories.

JADX recovers Java source from DEX files for source-level rules. Configure the launcher path, such as `/opt/tools/jadx/bin/jadx` or `C:\Tools\jadx\bin\jadx.bat`. ASAP invokes it with an output directory and the local APK path. On Windows, supported launchers are resolved to a Java classpath using their adjacent libraries.

## Apktool

Apktool provides optional resource and Smali decoding. Follow the [official installation instructions](https://apktool.org/docs/install/) and set the path to its launcher or JAR file. ASAP can invoke a JAR through Java directly:

```text
java -Xmx2048m -jar /path/to/apktool.jar d -f -o <output> <apk>
```

## Configuration

Copy [the tool configuration example](../examples/config.tools.example.json) and replace the paths with your installations:

```json
{
  "jadx": "/opt/tools/jadx/bin/jadx",
  "apktool": "/opt/tools/apktool.jar",
  "decompile": true,
  "workers": 4
}
```

Then check the paths and start the dashboard:

```bash
python3 -m asap doctor --config my-config.json
python3 -m asap web --config my-config.json --port 8765
python3 -m asap scan app.apk --config my-config.json -o results/app
```

If tool paths are omitted, ASAP looks for `jadx` and `apktool` on `PATH`. The `doctor` command reports Python, Java, and configured tool availability; it checks paths without launching the tools.

Use `--no-decompile` for a CLI scan, or `"decompile": false` in configuration, to inspect recoverable XML and assets without invoking decompilers. DEX code requires source recovery for Java/Kotlin rules. Reports show failed, unavailable, or timed-out decompilation in their coverage diagnostics.

The [full configuration example](../examples/config.example.json) lists category selection, exclusions, worker count, input limits, and suppressions. `tool_timeout` defaults to 600 seconds. Decompiler output is temporary; reports are written to the selected output directory.

## Analysis limits

`max_source_bytes` (256 MiB by default) and `max_files` (50,000 by default) bound the source text collected for analysis. When source collection reaches a limit, ASAP keeps the collected results and marks coverage as partial. The report identifies the reached limit; `--strict` returns exit code 2 for these diagnostics. Archive structure and extraction limits are checked before source collection and can reject the input.

To collect more source text, set `max_source_bytes` in bytes in your configuration file and rerun the scan with `--config`. Dashboard configuration is read when the server starts, so restart it after changing the file. The same APK's new scan is added to its workspace history.

## Firebase local inputs

Attach local Firebase Realtime Database Security Rules and exported data to the analysis input. These files are optional and are processed by `Insecure_DataStorage` alongside source-level database references.

```bash
python3 -m asap scan app.apk -o results/app \
  --firebase-rules ./database.rules.json \
  --firebase-data ./firebase-export.json
```

Both options also have string-valued configuration fields:

```json
{
  "firebase_rules": "/absolute/path/database.rules.json",
  "firebase_data": "/absolute/path/firebase-export.json"
}
```

```bash
python3 -m asap scan app.apk --config firebase-config.json -o results/app
python3 -m asap web --config firebase-config.json --workspace .asap-workspace
```

Relative attachment paths resolve from the process's current working directory, not from the configuration file. Use absolute paths for dashboard configuration. Attachments configured at dashboard startup apply to all scans served by that process; use files belonging to the APK project being reviewed.

Within an input directory or archive, ASAP automatically recognizes these basenames:

| Input | Recognized filenames |
|---|---|
| Realtime Database Security Rules | `database.rules.json`, `firebase.rules.json` |
| Exported database JSON | `firebase-export.json`, `database-export.json`, `rtdb-export.json` |

Explicitly attached files can have any filename. Supply a JSON Rules document with a top-level `rules` object and an exported JSON document for data. The reports include child paths, rule grants, and data types; scalar export values are omitted. Paths themselves remain visible and may contain record identifiers.

Traversal is bounded to 4,096 nodes and 64 levels. Paths longer than 2,048 characters are omitted; emitted path text is limited to 1 MiB per artifact. These limits are reported when reached. Source-reference inventories are capped at 512 paths per source file. Invalid JSON, unsupported rule conditions, and traversal limits mark coverage as partial. This analysis reads local files without querying the database. The [rule catalog](rule-catalog.md#insecure_datastorage-12) describes DS009–DS012.
