# Diagnostic workbench: decisions and open questions

Date: 2026-11-08. Status: proposed decisions from a read-only audit, not approved implementation changes. Supporting repository evidence is in [current state](diagnostic-workbench-current-state.md), API review in [gap analysis](diagnostic-workbench-gap-analysis.md), design in [architecture](diagnostic-workbench-architecture.md), and delivery/verification in [roadmap](diagnostic-workbench-roadmap.md).

## Executive assessment

1. **Suitability:** good as a small UI/product foundation, incomplete as a diagnostic architecture. The Iced message/state design can accept worker results and a contextual pane. Synchronous collection and string-only observations must be addressed before adding heavy diagnostics (`src/main.rs:121,265,770`).
2. **Reuse:** connection enumeration, persistent process cache, six-column table, filter grammar/autocomplete, sorting, refresh controls, themes and native frame. Keep these while making process refresh narrower and identity explicit.
3. **Biggest obstacles:** trustworthy process/service attribution across PID reuse and shared hosts; effective policy coverage; missing/audited evidence; temporal correlation; reproducible builds with external path and moving Git dependencies (`Cargo.toml:17,28,41`).
4. **Firewall reliability:** exact static-condition mismatches are feasible when inputs/coverage are known. Qualified candidate analysis is useful; universal policy-to-packet prediction is not. Direct correlated WFP block evidence confirms the recorded attempt, while friendly-rule, service and business-transaction attribution may remain unresolved.
5. **First value:** background collection and typed identities, followed by selected process/service details and a limited effective-rule mismatch explanation. The IFC8 remote-scope example demonstrates correlation without requiring trace setup or a full evaluator.
6. **Out of scope:** firewall rule management, service control, general Event Viewer, AD administration, patching, endpoint remediation, fleet administration, broad scanning and automatic AI diagnosis/repair.
7. **Preparation:** modest extraction into collector/model/state/filter/evaluation/UI modules; capability/freshness/evidence envelopes; tests around current behavior and identity; reproducible dependency policy. No major rewrite is recommended.

## Decision register

| ID | Proposed decision | Alternative considered | Tradeoff and rationale | Gate |
| --- | --- | --- | --- | --- |
| D01 | Keep Rust/Iced and existing table | New framework or complete redesign | Source has working table/filter/settings and an extensible message loop; rewrite adds risk without solving policy semantics | Phase 1 responsiveness measurements |
| D02 | Start with modules in one binary | Crate/plugin ecosystem, microservices | Small codebase needs explicit boundaries, not distribution or dynamic loading; reusable crate only for a real second consumer | Extract only as functionality arrives |
| D03 | Move blocking IO to bounded workers | More synchronous code; blocking API inside async task | Current update directly calls collector; heavy work would freeze interaction; worker ownership and completion generations are sufficient | Slow/failure/coalescing tests |
| D04 | Keep polling as authoritative inventory; supplement selectively | Replace with ETW/WFP events | Polling is simple and survives event loss; events improve visibility into short-lived attempts but need privileges, coverage and reconciliation | Phase 4 evidence/loss spike |
| D05 | Keep five-second configured default; decide startup enablement separately | Silently adopt premise of enabled-by-default | Source initializes `auto_refresh: false` at `src/main.rs:196`; product decision must be explicit | Record intended default before behavior change |
| D06 | Introduce typed identities/endpoints and provenance early | Add more columns to `SocketDisplay` | Strings cannot safely support scope/port/process-generation matching; display adapters preserve table investment | Phase 1/2 models and fixtures |
| D07 | Reuse netstat2 behind a collector boundary initially | Immediately rewrite all enumeration | Existing APIs cover all four requested tables; scope loss and unsafe boundary merit focused review, not a blanket rewrite | Scope/FFI spike before claiming full IPv6 diagnostics |
| D08 | Reuse sysinfo selectively; SCM for services | Per-row PowerShell/WMI; replace process library | Existing process cache is useful but refreshes unused fields; SCM supplies service identity without expensive row-level queries | Phase 2 overhead/ACL tests |
| D09 | Effective-store collection, initially NetSecurity if spike passes | Local rule enumeration; COM-only from outset | Effective policy and filter associations matter; PowerShell is higher overhead but can be cached; COM may omit required coverage/provenance | Phase 3 managed-endpoint/schema spike |
| D10 | Evaluate a declared subset with Match/Mismatch/Unknown | Reimplement full WFP arbitration or claim precise verdicts | Unsupported conditions and callouts cannot be guessed; useful explanations require less machinery and fewer false assertions | Mismatch/unknown fixtures and coverage UI |
| D11 | Evaluate program and service restrictions independently | Assume services invalidate program rules | Service hosting alone does not establish mismatch; shared PID attribution and WSH need independent evidence | Permanent regression tests |
| D12 | Read existing block evidence before enabling anything | Turn on auditing/logging automatically | Preserves read-only production use and avoids global event overhead; some diagnoses remain unavailable | Phase 4 no-setting-change gate |
| D13 | Findings have distinct fact/inference/failure classes | Generic risk score or red/green firewall badge | Certainty, severity, attribution and freshness differ; evidence references make conclusions reviewable | Golden scenarios/counterexamples |
| D14 | Bounded in-memory history first | Database/full continuous snapshot archive | Supports troubleshooting and keeps long monitoring predictable; some older evidence is intentionally unavailable | Soak/eviction tests |
| D15 | Optional selected diagnostics pane/action | Continuous full-machine enrichment; replacement dashboard | Retains simple connection workflow and contains costs/complexity | Keyboard, DPI, selection and latency checks |
| D16 | Redacted, explicit export; AI optional much later | Raw automatic report upload or model verdicts | Process args, SIDs and endpoints can disclose secrets/customer context; core diagnosis must stay deterministic/offline | Redaction preview and outbound-data checks |
| D17 | Make builds reproducible before expansion grows | Continue relying on local paths and ignored lockfile | Local dependency existence is not portable reproducibility; pin/lock choices need coordination with sibling repositories | Clean-machine build in later phase |

## Refactoring scope and alternatives

The largest recommended structural work is moving collection out of `App::update`, introducing typed state and extracting functions from `src/main.rs`. It is an incremental refactor, not a replacement of the application. A direct alternative—add PowerShell/firewall calls to the current refresh handler—has less initial code movement but demonstrably compounds UI blocking and cannot cleanly represent stale or partial evidence.

Replacing `advanced-table` is not justified now. Its external implementation eagerly constructs all cells (`C:/Rust Projects/advanced-table/src/table.rs:371`) but culls visible drawing/events. Cache parsed filters, normalized search keys and sorted indices by data/filter/sort generation first. Only consider table virtualization/replacement after measured 10,000-row interaction fails agreed gates.

Replacing `netstat2` is conditional. A small direct IP Helper collector may become the simpler option for retaining IPv6 scope IDs, separating table failures and hardening buffer handling. Review `netstat2-0.11.2/src/integrations/windows/socket_table_extended.rs:109–185`: it allocates a `Vec<u8>` by capacity, passes its pointer to Win32 and casts table pointers in parsing. This unsafe alignment/initialization/length boundary warrants a focused memory-safety review with actual allocation/error paths. The audit did not establish a runtime memory failure. Do not propose an entire networking rewrite to solve a narrow adapter problem.

A privileged helper or isolated collector process is a later conditional choice, not mandatory architecture. It can provide better least-privilege boundaries or killable hung collectors, but introduces IPC/authentication/packaging/lifecycle maintenance. Start with bounded workers and per-capability availability; adopt isolation only when an actual endpoint/access requirement justifies it. Do not install a persistent Windows service as a convenience.

## Open questions and required validation

| Question | Evidence already established | Remaining action / phase |
| --- | --- | --- |
| What Windows builds/architectures are supported? | No support matrix or packaged runtime requirements; custom frame targets Windows 11 behavior | Product deployment inventory; verify client/server desktop graphics, toolchain and bindings on agreed matrix / P1 |
| Should automatic refresh start enabled? | Five-second interval but startup disabled; no saved settings | Explicit product choice; preserve current behavior until decided / P1 |
| Can current dependency sources be reproduced elsewhere? | Absolute local dependencies, ignored local lockfile, Git master inputs | Record sibling revisions/licensing/availability; choose portable refs/toolchain; clean build / P1 |
| Can netstat2 retain scope and partial results safely? | Scope fields discarded; four-table errors abort combined result | Focused source/API review and controlled IPv6/FFI tests; upstream patch versus adapter / P1 |
| What process creation-time precision is sufficient? | Current display discards creation time; sysinfo exposes start time but not currently used | Inspect platform precision/availability; consider native FILETIME; define ambiguous key behavior / P1–2 |
| Can socket-level service attribution be improved? | SCM offers PID-to-many services; owner-module result can be process/service/component | Test TCP/UDP/IPv6 owner-module variants on shared hosts and restricted accounts; avoid undocumented tag lookup dependency / P2+ |
| Does ActiveStore cover required enterprise sources? | Microsoft documents combined effective policy; current app has none | Verify rule/filter/profile enforcement status and GPO/WSH/MDM/provider cases on actual target builds / P3 |
| Which COM/CIM/native interface meets effective-policy needs? | COM has useful read interfaces but local/effective distinctions; NetSecurity has richer associations | Benchmark and compare normalized schemas/provenance under constrained PowerShell / P3 |
| Can friendly firewall rule IDs be mapped from WFP filter IDs? | Events expose runtime filter IDs; lookup retrieves extant filter metadata | Document provider-specific mappings only if supported/tested; preserve unresolvable IDs / P4 |
| What audit events are enabled by default? | Audit CSP documents Off/None for both relevant client policy nodes; required subcategories and volume documented; no universal tested server/enterprise baseline | Review release/baseline documentation and clean-image effective audit policy for each supported OS; inspect target's actual policy / P4 |
| Which rights enable each capability without full elevation? | SCM/WFP/process APIs have distinct rights; channel and enterprise ACLs vary | Standard-user, delegated and elevated tests; show failures per field/source; do not infer visibility from token type alone / all phases |
| Which ETW/WFP event versions and fields are reliable? | APIs are versioned; net-event availability differs from Security auditing | Focused documentation and loss/tuple/direction schema tests on supported endpoints / P4 |
| Can temporary settings be restored safely? | Global settings can outlive process; GPO/other tools can change them | Keep unsupported by default; lab crash/reboot/conflict/recovery design before enabling mutation subfeature / P4+ |
| How should DNS/route/interface anomalies be interpreted? | Configuration can be collected; no application expectations exist | Validate DnsQueryEx cancellation/cache/NRPT behavior, interface-counter deltas, compartments and route semantics; limit conclusions / P3–5 |
| Are SCM/crash event schemas stable enough for findings? | Event Log interface available; no current parser | Validate provider/ID/version fields for service transitions, Application Error/WER and 4688/4689 where enabled / P4 |
| What are acceptable overhead/retention limits? | No benchmarks or soak tests; full process refresh and eager cell construction | Calibrate proposed p95/retention budgets on agreed hardware; 8-hour churn soak / P1 onwards |
| What endpoint data can be shared? | No report/export policy exists; broad initial sysinfo refresh can hold sensitive metadata | Define local privacy defaults and redact embedded finding/evidence text consistently / P6 |

In this table P1–P6 refer to roadmap phases, not the P0–P3 capability priorities used in the gap analysis.

## Technical guardrails

- An executable running as a service is not by itself evidence that its executable firewall rule fails. Application and service restrictions are independent dimensions.
- Lack of a candidate allow rule is not a confirmed block. A configured block candidate is also a configuration inference until direct evidence exists.
- A listening socket is not proof of remote reachability, application readiness or successful IFC8 transactions.
- A shared PID is not proof of a particular service's socket ownership. A historical PID is not today's process identity.
- A WFP permit does not prove end-to-end delivery; a WFP block event proves the recorded failure at its scope, not all future traffic or a friendly rule's causation.
- Missing/denied/stale/unsupported data must never silently become a successful empty result or a boolean non-match.
- Diagnosis stays read-only by default. Audit/logging/engine toggles are OS changes even when called “temporary collection”; any implementation needs distinct deliberate authorization and safe recovery.

## Sources and review status

The [gap analysis](diagnostic-workbench-gap-analysis.md) links the primary Microsoft pages reviewed for firewall filters/profiles, WFP arbitration/events, audit categories, SCM, event queries and network context. Conclusions about cost, architecture, budgets and phase sizing are engineering recommendations. No API feature was validated against live firewall/service/audit state during this audit. Unreviewed details and real-endpoint checks are explicitly listed above rather than presented as verified functionality.
