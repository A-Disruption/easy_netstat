# Workbench implementation

Implemented on branch `codex/diagnostic-workbench`, based on the five audit documents. Those documents remain a historical baseline, not a description of the updated code.

## Delivered components

| Roadmap area | Implementation |
| --- | --- |
| Foundations | `src/model.rs`, `src/inventory.rs`, `src/state.rs`: typed endpoints, exact native process creation identities, four independent IP Helper table queries, IPv6 scopes, initialized/length-checked buffers, single-flight refresh, stale completion protection, last-good partial data, bounded history. UI collector/evaluator jobs run through blocking workers. |
| Process/services | Native process path/creation time and narrow process refresh for inventory; on-demand CIM command line/owner and PID-to-many-services status/configuration. Native identity is checked before and after enrichment, allowing only CIM timestamp rounding. Shared-host membership never proves socket service ownership. |
| Effective firewall | `src/collectors/diagnose.ps1` queries ActiveStore profiles/rules/provenance and seven associated filter categories in one owned process. Each category fails independently. `src/firewall.rs` evaluates a declared subset with Match/Mismatch/Unknown and explicit unsupported conditions. Static program, service, direction, protocol, ports, addresses, profile and interface conditions are separate. Policy has a stable content version and a 60-second cache. |
| Evidence | Existing, bounded Security 5152/5157 and permit/bind/listen records; SCM/Application Error/WER context. `src/evidence.rs` parses named XML fields, not translated messages. `src/wfp.rs` looks up at most 16 current runtime filter IDs, preserving access/deletion/historical-mapping limitations. No audit/engine options are enabled. |
| Correlation | `src/diagnostics.rs`: versioned pure rules produce Observed/Inferred/Confirmed Failure findings, source references, timestamps, assumptions and next checks. Confirmation requires concrete tuple/direction/protocol and revalidated process lifetime. Matching configuration alone never confirms failure. Rule and finding output is capped. |
| Advanced workflows | Saved named filters/sorts/scenario expectations, in-memory and JSON baseline snapshots, process-generation-aware before/after comparisons, policy/network change indicators, redacted report preview/export, explicit DNS lookup. `src/storage.rs` enforces schema/size/count limits, local preferences replacement and create-new exports. |
| UI | `src/workbench_ui.rs`: settings-style diagnostics modal with Overview, Firewall rules, Process / services, Network, Events, History and Tools / reports tabs. The searchable/paged firewall browser exposes all collected rules independently of scenario analysis, plus candidate-only scope and full rule conditions/provenance. Availability appears in each tab. Existing full-width table/filter/sort/refresh/frame retained. Filter AST is cached and malformed input retains the applied query. |

## Important implementation choices

- Native IP Helper enumeration replaces the narrow `netstat2` path to retain IPv6 scope IDs, isolate table failures and use a checked FFI boundary. This is not a network-stack or UI rewrite.
- Service metadata uses one on-demand CIM enumeration rather than a new SCM FFI layer. It avoids per-row queries and can retrieve stopped expected services. This is slower than a native cached SCM map but does not affect inventory polling. Access limitations remain explicit.
- Windows PowerShell receives a fixed script plus JSON stdin. No input is interpolated into executable command text; no execution-policy bypass or profile scripts are used. Output/deadline/cancellation are bounded. Each owned collector is placed in a dedicated kill-on-close Windows job, so cancellation, errors, normal completion or application exit also terminate descendants and close inherited pipes. If containment cannot be established, diagnostics fail explicitly. Query errors are data, not successful empty collections.
- NetSecurity filter reads may require rights that rule/application/service reads do not. Partial policy is retained, with missing predicates Unknown. The integration endpoint demonstrated this exact access split.
- Filter InstanceID association is checked by integration assertions when the category is readable. Provider-specific schema changes can still produce incomplete coverage; no fallback silently assumes Any.
- Current policy cannot explain a historical event as though it were the event-time policy. Runtime filter metadata is a current lookup, not a persistent rule mapping.
- The 90-second deadline applies to the contained PowerShell job. In-process native Win32 queries cannot be forcibly interrupted safely; filter lookups check cancellation between calls and late results are discarded. They run off the UI thread, but a slow local WFP RPC can delay diagnostic completion/cancellation. No claim is made that all native calls stop exactly at the PowerShell deadline.
- Exact native process identity is authoritative; CIM creation dates may round sub-millisecond FILETIME digits. Enrichment requires unchanged native identity before/after and a consistent CIM timestamp/PID.
- All evidence parsing and deterministic rule evaluation run off the UI handler. Selection/input changes invalidate pending analysis results. Inventory scheduling coalesces repeated refreshes rather than building a backlog.
- The five-second configured interval and startup-paused behavior are preserved. History TTL is lazily pruned on successful samples; count/byte bounds prevent growth while monitoring. The accounted history-byte budget does not claim a whole-process memory ceiling.
- Reports deliberately omit arbitrary diagnostic strings because paths, names and secrets can be embedded in explanations or event XML. They retain anonymous references, certainty, fixed finding descriptions and condition outcomes. Full local snapshots are a separate sensitive workflow.

## Scope boundaries

The read-only roadmap path is implemented. Optional always-on WFP subscriptions, ETW/packet capture, audit/logging setup, privileged helper services and external AI explanations remain disabled/unimplemented. They were conditional/optional roadmap items, not prerequisites for diagnosis. They require separate provider/permission/privacy or recovery work and are not represented as available capabilities. DNS lookup is explicit network activity; no active port scanning, protocol replay or IFC8 payload injection occurs.

The matcher intentionally does not emulate all WFP layers/callouts, IPsec, authenticated bypass, dynamic RPC/address tokens, package/AppID restrictions, service-hardening semantics or path aliases. Unknown conditions prevent complete matching. A service expectation is user-supplied scenario context, not evidence of a particular service owning a socket.

The GUI is designed for Windows desktops; a cross-version Windows Server/GPO/MDM certification matrix and production eight-hour soak have not been completed here. Tests use no firewall or service mutations. Lab tests for recorded block events, policy precedence and protected-service scenarios are consolidated in the testing guide for the user's final testing pass.

## Build reproducibility

The binary lockfile is tracked, Iced is revision-pinned, source-generating/networked Fontello build steps are removed, and sibling paths are relative. Sibling UI sources are still external inputs; a clean checkout needs those repositories at compatible revisions. The implementation does not claim that Cargo.lock pins path-dependency contents. No sibling source repository is intentionally modified by this change.

Tested sibling inputs (all three working trees clean when checked):

| Repository | Commit |
| --- | --- |
| `widgets` | `2a0aa24ff091eaca352f82da1548ff4f5796786f` |
| `advanced-table` | `b64c670d1f85661473d5189b8ddb9b1098fb3216` |
| `iced-window-decorations` | `ecaff278111fa22c981624bdfb280f2fedfd49f6` |
