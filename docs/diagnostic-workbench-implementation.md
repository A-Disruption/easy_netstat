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


## Responsive diagnostic presentation — 2026-11-09

`src/diagnostic_style.rs` centralizes theme-aware evidence/status tones, labeled badges, section headings, key/value groups, summary metrics and notices. The modal root requests Fill in both dimensions; its scroll area consumes the remaining height instead of retaining the old 590-pixel content height. No sibling modal code was changed.

Overview leads with certainty counts and prioritized finding cards, each separating the explanation and next check; only six findings are expanded initially, with an All findings toggle. Evidence references remain optional. Firewall rule details separate application identity, traffic scope, profile/interface scope, policy provenance and per-condition evaluation. Process/service and network cards use subdued field labels and explicit status badges. Event records preserve their PID-only attribution caveat.

Colors supplement explicit labels: confirmed failure red; inferred findings/limited collection amber; observed context blue; known availability/condition matches green; unknown conditions neutral. A green rule condition is configuration evidence and never an observed traffic verdict. Tones use the selected Iced theme palette. Collection, policy evaluation and permissions are unchanged.


## Firewall relevance and administrator restart — 2026-11-09

Evaluator version 2 replaces executable/local-port-only candidate filtering with condition-based relevance. Known program/direction/protocol exclusions are removed from the shortlist. Positive exact executable or scenario-service identity retains useful near matches on other conditions; generic rules are shortlisted only when evaluated predicates match or remain unknown. Disabled rules remain available in the full policy browser. Broad matching block rules are preserved. Ranking is deterministic and occurs before the 2,000-candidate cap, so arbitrary enumeration order cannot push matching block/allow rules behind unknown entries.

Only identity-linked **allow** exclusions generate rule-specific inferred findings, with the excluding field names in the title and the identity/inclusion reason plus rule-versus-scenario values in the explanation. A nonmatching block rule is not presented as a problem. Policy summary precedes near-match findings and reports match/incomplete/near-match counts. Unverified relevance does not masquerade as an exact executable match; it remains included in analysis coverage but is collapsed in the default Relevant rules browser. The All collected browser is retained. Neither relevance nor matching configuration proves a traffic verdict.

`src/elevation.rs` reads TokenElevation and performs an explicit ShellExecuteExW `runas` relaunch on a background worker, with balanced COM/handle cleanup. It launches only current_exe with no forwarded arguments and uses the executable directory. There is no automatic elevation at startup or on access failure. The old process exits only on a successful Windows launch response with a process handle; UAC cancellation/errors preserve it. This response is not proof that the new GUI has finished initializing. Relaunch clears volatile session data as disclosed before the action. Alternate administrator credentials may use a different local saved-view folder. This action changes the application's privilege context, not firewall/audit/service configuration.

API references: [ShellExecuteExW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw), [Windows runas launch behavior](https://learn.microsoft.com/en-us/windows/win32/shell/launch).


Firewall evaluation now requires an explicit Inbound/Outbound choice instead of silently starting every selected connection as Inbound. Raw collection and full-policy browsing remain available before that choice. Saved views retain deliberately chosen directions; a newly selected connection requires confirmation again. Rule-specific finding cards link directly to the correct browser entry/page, clearing an unrelated previous search.
