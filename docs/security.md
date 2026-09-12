# Data handling and security

## Local analysis

ASAP reads APK archives and source files without installing or running the app. The analysis engine makes no network requests. Dashboard and report assets are bundled locally; opening a reference link visits that external site in the browser.

Reports contain static findings and code evidence. Review the reported context and coverage diagnostics when assessing a finding. Java/Kotlin flow analysis is limited to local expressions and does not establish runtime reachability.

## Reports and workspace storage

Evidence snippets mask string literals, and credential-shaped matches use redacted evidence. Reports still contain package names, component names, permissions, relative paths, and source hashes. Review the report before sharing it.

Uploaded files and generated reports remain in the workspace directory until removed manually. APK hashes identify exact file contents. Before reanalysis, the server checks the retained file against its recorded hash. Finding review records are stored separately in the browser and scoped by APK and source hashes. See [APK workspaces](workspaces.md) for storage and backup details.

## Input processing

Archive processing rejects unsafe paths, symlinks, special files, ambiguous names, and case collisions. Configurable limits cover file counts, expanded sizes, source sizes, and compression ratios. XML parsing rejects DTD/entity declarations; binary XML parsing validates chunk, string, and node boundaries.

External decompilers receive argument arrays without shell execution and run in temporary output directories. The configured timeout limits tool execution time. OS-level process isolation, network restrictions, and total CPU, memory, or disk quotas must be provided by the environment when needed.

## Local web server

The dashboard binds to `127.0.0.1` and is intended for one local user. Host validation, same-origin mutation checks, and a per-process CSRF token protect browser requests. These controls do not authenticate other local processes or provide a multi-user service.

The server accepts uploads up to 512 MiB, gives them generated file names, and limits the number of pending jobs. Report routes resolve completed jobs by ID. Rendered content uses escaping, DOM text operations, and a Content Security Policy.

The JSON report schema defines the output structure. SARIF `codeFlows` describe static evidence relationships; consumers should interpret them with the finding's confidence and coverage information.
