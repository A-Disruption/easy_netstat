# Consolidated verification and Windows acceptance guide

Run manual endpoint tests once the implementation is complete. Development verification is automated; no intermediate user testing is required.

## Automated checks

```powershell
cargo test --locked
cargo clippy --locked --all-targets --no-deps -- -D warnings
cargo fmt --package easy_netstat -- --check
cargo build --locked --release
```

Pure/model tests cover table-buffer bounds, socket formatting/scopes, state codes, process generation, refresh coalescing/pause/stale results, per-partition failures, history retention, exact-port filtering and grammar/negation/quotes, completion/paste, numeric sorting, candidate matching and unknown conditions, executable/service independence, event XML/PID/direction normalization, tuple/lifetime attribution, redaction, snapshot comparison, preference persistence and export overwrite protection. A 10,000-row table construction test exercises the existing widget path without live collection.

Windows tests additionally bind owned loopback IPv4/IPv6 TCP/UDP endpoints, enumerate them, query the on-demand read-only collector and validate schemas/category associations/own-process identity. Subprocess tests verify deadlines and error handling. Integration assertions are permission-aware: unavailable categories are allowed, successful categories must retain valid data. These tests do not prove successful collection from sources denied on the test endpoint.

An OS sandbox may deny IP Helper enumeration and native temporary-file replacement independently of ordinary user permissions. Run endpoint integration checks in a normal shell. Tests create and remove uniquely named temporary files and loopback sockets; no OS policy, rule or service state changes occur.

## Manual endpoint matrix

Start with a standard user on Windows 11, then repeat the relevant rows as an elevated user and on your actual Windows Server desktop builds. Include a domain/GPO endpoint and multihomed/VPN endpoint if these are deployment targets. Capture OS build, user context, app branch/build, configured refresh interval and capability states. Do not treat minimum Win32 API versions as application certification.

| Scenario | Procedure | Expected result |
| --- | --- | --- |
| Baseline workflow | Start, refresh manually, enable automatic refresh, pause, sort all columns, resize and search | Five-second initial interval; startup paused; manual refresh available; existing table remains primary |
| Paste and grammar | Paste `proc:IFC8 port:5001`; try quotes, negated groups and malformed trailing OR | Exact port filter; caret/completion works; invalid expression retains prior applied filter with error |
| Selection stability | Select a row, sort/refilter, refresh and let the process exit | Selection remains tied to identity; vanished row is historical, never reassigned to another PID instance |
| Diagnostics popup | Select a row, click Diagnostics, visit every tab; close with title button, Escape and backdrop; open Settings | Row selection does not auto-open the popup; table stays full width; same themed draggable/resizable modal as Settings; only one popup active |
| Firewall discoverability | Collect diagnostics, open Firewall rules, search program/service/port/scope/source, page/select rules and toggle All collected / Examined candidates | Raw collected rules remain visible without completed analysis; profiles/default actions, full rule predicates/provenance and missing-filter status are explicit |
| Responsiveness | Keep typing/scrolling while Diagnose and policy refresh run; cancel/change selection/close | UI responds; stale results do not appear on another connection; owned collector exits on cancellation |
| Process context | Compare selected path/PID with Task Manager; inspect optional owner/command line | Exact identity, denied/exited fields labeled; sensitive command line only in expanded local details |
| Services | Inspect an own-process service and a shared host; enter a known stopped expected service | All visible associated services; shared PID is not a fabricated socket owner; stopped status is fact, causation remains inference |
| IPv6/scopes | Inspect IPv6 loopback and, where available, link-local bindings on two interfaces | Bracketed endpoints and distinct scope IDs; no guessed link-local interface |
| Partial access | Diagnose standard-user, then elevated | Readable rule/filter categories survive independently; denied categories are Unknown, not Any or no rules |
| Network context | Compare interfaces/profiles/DNS/routes with read-only Windows tools | Per-interface category, current configuration times, absolute counters labeled; wildcard listener does not pick an interface arbitrarily |
| Saved views | Save filter/sort/peer/service/port expectation; restart and load | Local versioned view restored; no diagnostic query or configuration change merely from loading |
| Baselines | Capture, change a lab process/connection, compare; save/load JSON | Generation-aware counts, policy/network indicators where collected; cross-session/partial comparisons clearly qualified |
| Privacy | Preview/export a report with synthetic secrets in local process arguments and names | No arguments, paths, accounts, addresses, rule names or raw XML leak; full snapshots explicitly remain sensitive |
| Files | Export to a new path, then repeat to the same path; import malformed/oversized JSON | Existing file preserved; bounded schema/size errors; import executes nothing |
| DNS | Resolve a chosen hostname, an invalid name, and test offline | Explicit lookup only, bounded latency, errors visible; answers are not claimed to be the application's own cache |

## Firewall/evidence lab scenarios

Use disposable authorized endpoints. Arrange lab rules/audit configuration using your normal administration tools; the workbench itself will not make those changes. Leave production policy untouched.

1. Start an IFC8-named fixture listener at `0.0.0.0:5001`. Select it; enter the actual local interface address, a concrete peer endpoint, direction and interface. Use an effective inbound executable allow rule limited to another remote subnet. Expect **Inferred** remote-scope mismatch with separate program/port/profile outcomes. No block is confirmed by this configuration alone.
2. Run the executable as a service with an application rule whose service filter is Any. The application condition must not fail solely because of service hosting. Test a separate service-specific restriction and shared-host ambiguity.
3. Vary one predicate at a time: executable directory, service, protocol, local/remote port, IPv4/IPv6 address/CIDR/range, profile, interface and allow/block action. Unsupported dynamic/security conditions must stay Unknown.
4. Test overlapping ordinary allow/block rules, disabled/inapplicable rules, default policies, inbound-exception blocking, and GPO local-rule merging disabled. Candidate explanations remain configuration inferences; do not expect a universal WFP verdict simulator.
5. With existing failure auditing enabled in the lab, reproduce a known blocked attempt. A corresponding 5157 must match tuple, direction, protocol, time and process lifetime before the selected process gets **Confirmed Failure**. 5152 confirms a packet drop, not every retry/application transaction. Inspect filter metadata and its current-versus-historical limitation.
6. Test wrong tuple, reversed direction, a reused PID, old process lifetime, unavailable filter ID and a policy change after the event. These must not cause incorrect process/rule attribution. Permit 5156 must not be labeled end-to-end success.
7. Repeat with auditing disabled, Security access denied, no matching records and a high-volume/rotated log. Capability/gap labels must distinguish these states; the app must never enable auditing to make a diagnosis succeed.
8. Stop/restart a fixture service and generate a fixture process crash using your lab tools. Compare SCM/Application Error/WER records with app findings. Structured identity context is Observed; restart/crash causation is not fabricated from nearby timestamps.

## Performance/soak

Use representative connection counts (1,000 and 10,000 where practical) and the default five-second interval. Record input-to-filter latency (including the intentional 250 ms debounce), scroll/sort latency, inventory duration, CPU/private bytes and process handles. Heavy diagnostics must not block the UI or queue unlimited inventory jobs. The 10,000-row construction test is a regression check, not an end-to-end p95 benchmark.

For an eight-hour churn run, observe history hitting a retention plateau and verify no sustained handle/thread growth. History accounts up to 32 MiB/50,000 changes and lazily expires old changes on successful samples; it is not a hard cap on total application memory. Capture one baseline at a time and run at most one diagnostic collector and one evaluator concurrently. Cancel and exit during collection; ensure no owned PowerShell child remains.

Finally, compare OS configuration before/after using your standard read-only inspection tools. The expected difference is **none**: no firewall, auditing, service or network-setting mutation is part of the implementation.
