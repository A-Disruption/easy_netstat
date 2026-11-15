# Diagnostic workbench: current-state audit

Audit date: 2026-11-08. Baseline commit: `02c1aa90882bcdf37191126503a2d6fc4624c135`.

## Method and evidence limits

This is a documentation-only audit. All tracked source/configuration files were inspected, with binary assets inventoried and relevant cached dependency implementations inspected read-only. The initial working tree was clean. There were eight tracked files: `.gitignore`, `Cargo.toml`, `build.rs`, `src/main.rs`, `src/icon.rs`, `fonts/icons.toml`, `fonts/icons.ttf`, and `assets/netstat-rust.ico`. There was no README, CI configuration, integration-test directory, release manifest, Windows support matrix, or prior architecture documentation. `Cargo.lock` exists locally but is ignored and untracked.

**Verified** below means established from source, not a live GUI test. **Dependency-verified** means established from the locally resolved dependency source, which another checkout may not resolve identically. Performance consequences are analysis, not measured timings. No application execution, compilation, dependency installation, firewall queries, trace sessions, audit-policy changes, or Windows acceptance tests were performed. In particular, `build.rs:3` invokes a generator that writes tracked icon source/assets; building was avoided to respect the requested write boundary. Existing `target` binaries are not proof of the behavior of this commit.

Windows mechanisms were checked against Microsoft documentation; implementation choices and endpoint tests remain proposals. See the [gap analysis](diagnostic-workbench-gap-analysis.md) for API references and the [roadmap](diagnostic-workbench-roadmap.md) for validation still required.

## Architecture and dependencies

| Component | Verified implementation and reference | Implication |
| --- | --- | --- |
| Application | Rust 2024 binary, version 0.1.0, `Cargo.toml:1`; almost all logic in 1,236-line `src/main.rs` | Small enough for incremental extraction; no rewrite needed |
| GUI | Iced `0.15.0-dev`, patched to Git `master`, `Cargo.toml:7,40`; application/update/view/subscription entry at `src/main.rs:694` | Message-driven state architecture can accept background completion messages |
| Runtime features | Iced Tokio, advanced, debug, canvas, image, SVG, Markdown, QR features, `Cargo.toml:7` | Tokio availability does not mean collectors run asynchronously |
| Custom UI | Absolute path dependencies `widgets`, `advanced-table`, `iced-native-frame`, `Cargo.toml:17` | External sibling repositories are required; their revisions are not captured here |
| Collection | `netstat2 = 0.11.2`, `sysinfo = 0.40`, `Cargo.toml:20` | Reusable API-based collection and process cache |
| Assets/build | `image 0.25`, Git-master `iced_fontello`, Windows `winresource`, `Cargo.toml:23,28,33`; `build.rs:1`; generated `src/icon.rs:1` | ICO decoding and resource embedding; build can regenerate tracked files |
| Presentation | Native themed frame, settings modal, autocomplete popover, table; `src/main.rs:364,515,694` | Existing widgets can support a contextual pane |

The local ignored lockfile resolves Iced to `8ff48c42b0d5188223501ea1ccc506fd5beaf36a`, `iced_fontello` to `2e6d61ee5a869443a249e7ee46a460665ce4969d`, `netstat2` to 0.11.2 and `sysinfo` to 0.40.1. These are audit reproducibility details, not repository guarantees. Cached `sysinfo-0.40.1/Cargo.toml:14` declares Rust 1.95; the application does not declare a toolchain or MSRV. Do not infer application Windows compatibility from an individual Win32 API's minimum version.

The resolved `iced_fontello` generator also conditionally contacts `fontello.com` when its configuration hash changes or the TTF is absent, then writes the TTF and generated Rust module (`C:/Users/ktwinam/.cargo/git/checkouts/iced_fontello-42cec9c51ace435d/2e6d61e/src/lib.rs:241,266,311`). Existing matching generated files can avoid that path. This is a build-time reproducibility/offline-build concern, not evidence of application-runtime telemetry.

## Collection and identity

`App::new` creates a persistent `sysinfo::System` with `RefreshKind::everything()` and queues one `RefreshData` message (`src/main.rs:176`). The refresh handler calls `get_netstat` directly, maps sockets to display rows, and replaces the previous result (`src/main.rs:265`). `get_netstat` first refreshes all processes, removing dead entries, then requests both address families and both protocols (`src/main.rs:770`). No `netstat.exe`, PowerShell, WMI, shell parsing, DNS lookup, service query, firewall API, WFP API, or Event Log API appears in application code.

Dependency verification: under `C:/Users/ktwinam/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/netstat2-0.11.2/src/integrations/windows/`:

- `api.rs:7` builds four table iterators, using owner-PID tables for IPv4 TCP/UDP then IPv6 TCP/UDP. Errors propagate with `?`; one failing table prevents a combined successful result.
- `socket_table_extended.rs:109` calls `GetExtendedTcpTable` with `TCP_TABLE_OWNER_PID_ALL`; `:147` calls `GetExtendedUdpTable` with `UDP_TABLE_OWNER_PID`. These are IP Helper API calls, not command execution. Buffer-size retries are capped after more than 100 iterations.
- `socket_table_extended.rs:12,37,64,86` converts OS rows and supplies one owning PID per row. IPv6 local/remote scope IDs are explicitly omitted (`:52,55,101`). A normalized model alone cannot recover these lost values.

`SocketDisplay::from_socket` retains only strings for protocol, state, local address, remote address, PID, and process name (`src/main.rs:121`). It uses only the first associated PID and joins by numeric PID against the process cache (`:151`). Missing processes become `Unknown`; missing PID becomes `-`. Reasons such as access denied, process exited, PID zero, or collection race are not distinguished. Full paths, command line, account, creation time, service membership, and source timestamps are discarded or never requested explicitly for display.

Cached `sysinfo-0.40.1/src/common/system.rs:316` shows ordinary `refresh_processes` requests CPU, memory, disk usage, executable if unset, and tasks. The broader initial refresh additionally requests user, environment, command line, working directory, GPU data, etc. (`:2651`). Most of this exceeds the displayed name/PID requirement; some sensitive information may reside in the process cache even though there is no export feature. Windows process access attempts query/read access and falls back to limited query access (`sysinfo-0.40.1/src/windows/process.rs:72`). Individual process details can remain unavailable.

The process refresh precedes four non-atomic socket enumerations. A process may exit or a PID may be reused between those operations. Current data has no process-generation identity to detect misattribution. No process restart or termination history is maintained.

## Verified user behavior

| Feature | Actual source behavior | Limitation or discrepancy |
| --- | --- | --- |
| Initial load | One startup refresh (`src/main.rs:203`) | System initialization can panic before graceful display |
| Automatic refresh | Default interval is five seconds (`:22`); **enabled flag starts false** (`:196`); timer exists only when enabled (`:552`) | Task premise of automatically refreshing by default differs from source |
| Pause | Turning off “Refresh automatically” removes the timer (`:529,557`) | Manual refresh still works; no separate frozen-view/history semantics |
| Interval | Digits only; positive `u64` updates last valid value; empty/zero/overflow retains previous interval (`:235`) | No practical upper bound or clear invalid-input message; extreme duration needs validation |
| Manual refresh | Refresh icon sends `RefreshData` (`:457`) | Runs same synchronous work |
| Table | Six columns, sortable/resizable and horizontally/vertically scrollable (`:386`) | No application-level selected-connection state, details pane or diagnose action |
| Sort | Protocol/state/endpoints lexicographic, PID numeric, process case-insensitive (`:743`) | Endpoints are not numerically ordered IP/port tuples; unknown PID first when descending |
| Filtering | Field aliases and boolean expression tree (`:793–1126`) | No saved views, port-specific numeric field, validation or parser diagnostics |
| Autocomplete | Field/value suggestions, context filtering, ordered deduplication, ten shown; arrow/Enter/Tab/Escape handling (`:564,593`) | Whole candidate set scanned before truncation; context uses whitespace splitting rather than the full tokenizer |
| Themes | Nord initially; theme selector in settings (`:199,536`) | No persistence across application restarts |

Search supports `protocol/proto`, `process/proc`, `state`, `local/localaddr`, `remote/remoteaddr`, `pid`, plus unqualified search across all six columns (`src/main.rs:1067`). Matching is case-insensitive; plain text is a substring, quoted text is exact, leading/trailing `*` selects suffix/prefix/contains. Interior wildcards are not a glob language (`:884`). Spaces imply AND and `|`, `!`, parentheses are recognized. The optimizer changes repeated direct criteria for the same field in an AND group into OR, including unqualified `Any` criteria (`:1084`). For example, `proc:a proc:b state:Listen` means `(proc:a OR proc:b) AND state:Listen`. Recursive optimization does not descend through `Not`, so behavior is structurally dependent. Invalid/trailing operators and unmatched delimiters do not produce errors; empty AND groups match everything. These semantics need characterization before changing them.

The input placeholder advertises `port:5013` (`src/main.rs:426`), but `parse_single_criterion` does not recognize `port`; it searches literally for `port:5013` across columns. `local:5013` or `remote:5013` works as substring matching and is not an exact port predicate. `FilterChangedImmediate(value)` ignores `value` (`:262`); paste is wired to that message (`:429`), so pasted content may not update staged/applied text correctly. This is a source-level defect candidate requiring a GUI reproduction, not a validated paste result.

## Protocol coverage and absence of history

- TCP listeners and connections: collected with state; no inference of traffic direction or handshake completion beyond displayed state.
- UDP: local bound endpoints are shown with remote `*:*` and state `-` (`src/main.rs:144`). This is not a list of remote UDP peers or connection sessions. A UDP bind is not proof of application readiness.
- IPv4/IPv6: both requested; IPv6 rendered as `address:port` without brackets (`:140`), making text ambiguous. Lost scope IDs additionally impede link-local/interface correlation. An IPv6 wildcard listener alone does not prove dual-stack behavior.
- Each refresh replaces all rows. There is no previous snapshot, diff, first/last-seen time, transition log, persistence, reporting or saved diagnostic view (`:268`). Intermediate TCP states and connections shorter than the polling interval can be missed. Absence from a later successful sample is disappearance, not proof of graceful closure or a crash.

## Responsiveness, errors and reliability

The UI update path blocks on all process and socket enumeration. `Task::done` only schedules a message; it does not move collection to a worker. `DataState::Loading` is rendered but never assigned (`src/main.rs:115,416`). No cancellation, request deduplication, timeout, backoff, collection health, last-success timestamp, or partial-result model exists. A socket enumeration error replaces good data with a whole-page error (`:268,418`). Process initialization uses `expect` (`:182`); icon decode failures silently omit icons (`:39,56`). No application logging or explicit elevation request is present.

Filtering parses once per `view` sweep, not once per row (`src/main.rs:367`), but still reparses on subsequent views. Matching repeatedly lowercases values/patterns, and process sorting allocates lowercase strings in comparisons (`:743,874`). Every view constructs a filtered row vector, potentially sorts it, and builds six cell widgets per row. The 100 ms debounce subscription runs even when idle/automatic refresh is off; `last_keystroke` is never cleared after application, so it repeatedly assigns the applied filter after the threshold (`:289,555`). It can cause redundant work; exact Iced redraw frequency has not been profiled.

The external table was inspected read-only: `C:/Rust Projects/advanced-table/src/table.rs:371` eagerly constructs every row's cells. It also culls visible drawing/events (`:657` and visible-range call sites); do not describe it as having no viewport optimization. Full widget construction still scales with total visible-result count, not viewport count. Profile 1,000/10,000-row loads before replacing it or introducing virtualization.

Memory stores one displayed snapshot plus a process cache and autocomplete, with no growing history. It is not bounded by a configured maximum and has not been soak-tested. Adding history without explicit count/byte/time bounds would change that risk substantially.

The app does not require elevation explicitly. Ordinary owner-PID enumeration is intended as a non-administrative baseline, but process fields may be restricted; no standard-user, hardened-server or protected-process test was run. No supported Windows versions are declared. The native frame targets Windows 11 caption behavior, but that is not evidence that Windows 10 or Windows Server fails or succeeds. Validate packaged graphics/runtime behavior on each supported client/server desktop; a GUI on Server Core is not an assumed target.

## Tests and recommended preparation

Five unit tests exist at `src/main.rs:1161–1236`: autocomplete values for endpoint/PID fields, contextual suggestions, alternatives on the same field, icon decoding, and completion spacing. The helper calls `App::new`, so otherwise logical autocomplete tests also initialize real system information (`:1145`). There are no application tests for polling, sort order, parser edge cases, process identity, permissions, partial failures, concurrency, Windows policy, or UI responsiveness. Tests were inspected, not executed.

Prepare with small changes in a later implementation phase: isolate the collector and typed model, move blocking work to bounded background execution, retain last-good/partial data, minimize process refresh fields, characterize filters, and make builds reproducible. Preserve the table, Iced update/view design, autocomplete behavior and native frame. New Windows capabilities should be modules in this binary initially. Major UI/framework replacement, a plugin host, or separate services are not justified by repository evidence.
