# Diagnostic workbench: implementation roadmap

Date: 2026-11-08. Planning only; no application changes were made. Read alongside [current state](diagnostic-workbench-current-state.md), [gaps](diagnostic-workbench-gap-analysis.md), [architecture](diagnostic-workbench-architecture.md), and [decisions](diagnostic-workbench-decisions.md).

## Delivery strategy and effort

Preserve the current connection-table workflow and five-second configured interval. Implement the six phases below, but bring basic snapshot differencing and a narrow deterministic finding into earlier phases: history infrastructure is needed before WFP evidence, and policy mismatch explanations deliver value before a broad correlation catalog. Do not wait until Phase 5 to make collected details intelligible.

Relative effort: S = roughly one contained feature; M = several features/integration points; L = significant Windows integration and endpoint matrix; XL = high uncertainty or scope deliberately deferred. These are relative sizes, not calendar estimates. Firewall/evidence spikes must narrow scope before estimating delivery dates.

| Phase | Effort | Depends on | Independently useful outcome |
| --- | --- | --- | --- |
| 1. Foundations | M | Current source and available dependency repositories | Responsive, reliable viewer with honest freshness/errors |
| 2. Process/service context | M–L | Phase 1 typed identity/background collection | Explains owner/service and observed listener changes |
| 3. Effective firewall intelligence | L | Phase 1; Phase 2 identity; interface/profile context | Explains candidate rules and condition mismatches |
| 4. Targeted diagnostic evidence | L | Phase 1 bounded state; Phase 2 identity; Phase 3 policy references | Shows actual recorded block attempts and their attribution limits |
| 5. Cross-source correlation | M–L | Earlier typed evidence; each rule gated by source availability | Ranked, explainable multi-source findings |
| 6. Advanced workflows | M per workflow; AI/capture L | Stable evidence/schema/privacy model | Reusable views, snapshots and shareable reports |

## Phase 1 — architectural foundations

**Objective:** remove demonstrated expansion blockers without changing frameworks or redesigning the GUI.

Concrete tasks:

1. Extract typed endpoint/connection/process-reference models, a collector boundary and pure filtering/sorting. Retain display adapters for the existing table. Preserve unknown/partial states rather than serializing everything as strings.
2. Move connection and narrow process enumeration to a single-flight background worker. Coalesce refresh requests; return generation-tagged results; preserve last-good data and per-table collection errors. Add last-success/start/end timestamps, health and missed-sample indicators.
3. Split enabled/pause behavior from interval. Preserve current startup-off until product choice is recorded; keep five seconds as configured default. Bound interval input and show invalid states. Ensure manual refresh remains available.
4. Characterize current filter behavior, then correct the `port:` placeholder or deliberately implement a typed port filter. Resolve the ignored paste payload and repeated debounce application. Define error treatment for malformed input and preserve documented same-field OR semantics unless explicitly changed.
5. Add bounded current/previous snapshot differencing primitives and process-generation keys, including unknown creation time. Full history UI can wait.
6. Review IPv6 scope fidelity and the unsafe IP Helper buffer boundary in `netstat2`. Choose a minimal adapter fix/upstream patch or narrow native collector if required; do not replace working collection solely for stylistic consistency. Bracket IPv6 display endpoints.
7. Establish reproducible dependency/toolchain policy: record/track an appropriate binary lockfile, replace machine-specific paths with documented reproducible references when authorized, pin moving Git sources as appropriate. Arrange icon generation to avoid unexpected tracked-source rewrites in checks. These are future repository changes, not part of this audit.

**Risks:** Iced development API churn, external custom-widget revisions, a background task that still performs blocking IO on an async executor, accidental filter semantics changes, disappearing/reused identities, shutdown with pending work. Scope restoration and mutation helpers are not prerequisites.

**Acceptance criteria:** collection never runs in `view`/the UI update handler; only one inventory job is in flight; UI shows last-good data and collection failures separately; stale completions cannot overwrite newer state; one protocol-family failure does not silently appear as an empty successful inventory. TCP/UDP/IPv4/IPv6 and current manual refresh/filter/sort remain usable. Settings clearly show whether automatic refresh is enabled. Proposed responsiveness and memory targets below pass on reference hardware.

**Automated tests:** fake slow/failing/partial collectors; refresh coalescing; pause/manual/timer transitions; stale result rejection; shutdown/cancel semantics; typed IPv4/IPv6/scope and numeric sorting; filter aliases, same-field OR, negation/groups, unknown prefixes, malformed input, quoting/wildcards and paste reducer; disappearance versus sample gap; process-generation mismatch. Extract fixtures so logical tests do not call `App::new` and enumerate the live system as current autocomplete tests do (`src/main.rs:1145`). Use no real policy mutation in unit tests.

**Windows verification:** compare a known controlled TCP listener and UDP bind in both families with `Get-NetTCPConnection`/`Get-NetUDPEndpoint` or `netstat -ano`; account for sample timing. Check IPv6 loopback and two link-local interfaces, disconnected stack/table failure, standard-user operation, manual refresh while paused, invalid interval/paste, sorting, keyboard navigation, DPI and closing during collection. Measure 1,000 and 10,000-row scenarios using synthetic fixtures, then a representative endpoint. No need to create production connections simply to hit a row count.

**Useful delivery:** yes, the existing viewer becomes safer and more responsive before new diagnostic intelligence.

## Phase 2 — process and service correlation

**Objective:** identify what owns a selected endpoint and explain relevant service/listener observations.

Concrete tasks:

1. Add stable row selection and a collapsible contextual pane, preserving the main table.
2. Show PID, process creation identity, executable name/path and collection times; on-demand command line and token/account only where available. Cache by process instance; retry transient absence with a bounded policy.
3. Build SCM PID-to-many-services map; enrich selected services with state/start type/configured binary/account. Label shared-host association and incomplete visibility. Do not assume configured service binary equals current process image.
4. Add bounded first/last-seen and sampled changes; keep terminated-process identity for the retention period. Show stale selected rows explicitly.
5. Add basic adapters/address/profile context needed by Phase 3. Retain interface identity and scope IDs. Use user-defined expected service/port/address, when supplied, for a narrow stopped-service or unexpected-bind finding; do not infer expectations from a process name.
6. Introduce finding/evidence envelope now, with Observed/Inferred/Confirmed Failure types, although this phase need not emit confirmed network blocks.

**Dependencies:** Phase 1 worker, typed observations, identity and tests; SCM bindings; selected-pane support in current custom table or cell interactions. Inspect its available selection API before adding a parallel selection mechanism.

**Risks:** shared service hosts, process wrapper binaries, restarts during enrichment, PID reuse, permission-limited service enumeration, sensitive command lines, network profile changes, pane width at the current fixed minimum window size.

**Acceptance criteria:** selected own-process service maps correctly; shared host shows all visible associated services and no fabricated socket owner; stopped service remains inspectable through an expectation/recent history even without a live row; restart produces a distinct process instance. Unknown access and no association are visibly different. Detail collection does not change the five-second inventory cadence. No service control commands exist in the diagnostic flow.

**Automated tests:** PID reuse across snapshots and late detail results; missing/low-precision creation time; shared-host many-to-one associations; stopped/start-pending state; configured command parsing versus runtime path; negative-cache expiry; byte/count/time eviction; saved selected identity across sorting/refiltering; field availability and command-line redaction.

**Windows verification:** use a disposable test service and a shared service host; compare SCM output with `sc.exe queryex` / read-only `Get-CimInstance Win32_Service`, Task Manager and process paths. Restart/stop the fixture service only in an authorized lab. Verify protected processes, a service with restricted ACL, command-line secrets in display/export previews if introduced, and multiple adapter profiles. Verify loopback-only versus wildcard bindings without treating either as remote reachability proof.

**Effort/usefulness:** M–L; useful on its own for IFC8 ownership, stopped/restarting service and wrong-bind diagnosis.

## Phase 3 — effective firewall intelligence

**Objective:** show effective policy candidates and explain specific condition mismatches, without claiming an exact WFP verdict.

Concrete tasks:

1. Run a short feasibility spike comparing NetSecurity ActiveStore, associated filters and profile settings with COM/native alternatives on standalone, GPO-managed and, if supported, MDM-managed endpoints. Capture schema/provenance/permissions and query cost. Select one primary read-only collector.
2. Collect effective profile/default/merge/inbound-exception settings, interface network category, applied rule provenance and all associated filter categories in bounded background batches. Use structured data; report unsupported/provider-specific fields.
3. Cache policy by content version and age. Add explicit refresh; keep failed refreshes separate from last successful policy. Avoid per-rule or per-row PowerShell startup.
4. Add TrafficScenario inputs for inbound listener analysis: concrete local address/interface, remote address and port, direction/protocol/time. Preserve observed versus hypothetical inputs.
5. Implement Match/Mismatch/Unknown for common full-path, service Any/specific, protocol, static port/address ranges, profiles and interface conditions. Add condition coverage and candidate explanation UI; advanced tokens/security conditions remain Unknown.
6. Identify ordinary overlapping block candidates and absence of visible allow candidates as qualified inferences only. Add the IFC8 remote-scope mismatch demonstration from architecture.

**Dependencies:** typed identity and network context; a tested program-path normalization policy; effective-store/schema spike. Service-specific matching depends on adequate service attribution; ambiguity is not a boolean false.

**Risks:** GPO local-rule merging, policy changes during multi-query collection, constrained PowerShell, unsupported dynamic conditions, AppID/security/IPsec/WSH rules, multiple profiles, historical policy mismatch. A service-hosted executable must not be deemed mismatched merely because it is a service.

**Acceptance criteria:** test fixture explains program/service/protocol/ports/addresses/profile/interface separately, naming exact mismatch and inputs. Executable allow rule with service Any remains a candidate for an own-process service. A service-specific rule needs its separate condition checked; shared-host uncertainty remains Unknown. GPO-effective rules differ correctly from local-only configuration. No “blocked” verdict arises solely from missing allow candidates, matching block configuration or incomplete collection. Unsupported conditions prevent a complete match assertion. Disabling app diagnostics makes no policy changes.

**Automated tests:** table-driven static IPv4/IPv6/CIDR/range/Any/port cases, direction reversal and listener wildcards; service Any/specific/shared-host cases; full-path mismatch and unavailable paths; dynamic token/security condition Unknown; missing filter category; duplicated display names but different IDs; disabled/inapplicable rule; effective local-merge fixture; profile/interface restrictions; ordinary block/allow overlap; cache staleness and inconsistent snapshot. Assert no configuration-only input can emit Confirmed Failure.

**Windows verification:** lab rules varying one condition at a time (program, service, port, address, profile, interface), explicit block overlap, firewall disabled/profile defaults, block-all inbound, GPO merging disabled and constrained-shell failure. Compare exported normalized data against read-only NetSecurity queries and Windows Firewall advanced console. Attempt actual traffic only in the lab and record separately whether policy inference agrees; policy agreement alone is not direct failure evidence. Recheck MDM/provider coverage before advertising it.

**Effort/usefulness:** L; independently useful and the best early demonstration of configuration correlation.

## Phase 4 — diagnostic evidence

**Objective:** correlate existing recorded blocks and relevant service/process events with a selected traffic scenario.

Concrete tasks:

1. Read actual audit capability/settings; query existing Security 5157 first, 5152 when justified, and already-enabled permit/bind/listen events. Use provider/channel/ID/time bounds, structured schemas and read-access status.
2. Add targeted SCM service events and Application Error/WER context, scoped to service/process/time. Validate IDs/schemas before using them to infer restart/crash causes. Consume existing 4688/4689 only where available and appropriate.
3. Store event identities/bookmarks, provenance, collection gaps, normalized tuple/direction plus original fields and schema versions. Correlate against historical process instances and scenario, keeping ambiguous matches.
4. Look up an extant WFP filter runtime ID promptly; retain provider/layer/filter information without promising friendly-rule mapping.
5. Spike native WFP event subscriptions as an optional complement, with OS-version negotiation, bounded callback queue and loss counters. Keep polling as inventory. Defer ETW/packet capture unless this evidence fails a concrete user scenario.
6. Keep audit/engine/logging enablement out of read-only Diagnose. If a future temporary setup is implemented, make it an explicitly authorized subfeature with durable recovery/conflict checks; otherwise provide administrator guidance for lab setup.

**Dependencies:** identity/history/evidence envelopes from Phases 1–2, policy references from Phase 3 where available; channel and WFP access. A block event remains useful even when policy collection is unavailable.

**Risks:** events disabled or inaccessible, high global event volume, log rotation/clear, event delivery loss, transient/deleted filter IDs, PID reuse, schema/localization differences, clock skew, accidental system-wide audit enablement. Default settings must be tested on clean images rather than assumed from one workstation.

**Acceptance criteria:** a lab 5157 can confirm the particular attempted tuple at its timestamp with inspectable evidence; a mismatched PID/time/path remains unassociated or ambiguous. 5152 is labeled packet drop. No events found is distinguished from disabled audit, denied channel, truncated window and no observed matching records. Existing 5156 is not presented as delivery success. Bounded queries/callbacks do not affect inventory responsiveness. Cancelling/shutting down closes only owned handles/sessions. Default mode makes no OS setting changes.

**Automated tests:** event XML fixtures for versions, localized messages but stable field names, hex/decimal PID values, inbound/outbound local/remote mapping; missing/unknown event fields; wrong tuple/path/PID reuse/time; log epoch/rotation, duplicate record delivery, bookmarks and overflow; deleted filter/provider; query deadline and cancellation; blocked capability; loss counters and evidence expiry. If temporary setup is built, fault-inject every apply/restore step and concurrent policy changes; process-kill recovery cannot be replaced by unit tests alone.

**Windows verification:** authorized two-endpoint lab generates allow and block attempts in both directions/families with known process lifetimes. Compare event records and actual traffic times. Repeat auditing on/off, read denied, log rollover, rapid process restart and BFE/filter replacement. Observe 5157 and 5152 independently; confirm reported global event-volume impact. Test a supported third-party WFP provider if its attribution is advertised. If optional tracing/setup exists, test cancel, crash, reboot, other administrator changes and restoration conflicts; never perform this destructive verification on production servers.

**Effort/usefulness:** L; independently valuable direct evidence, without needing the complete Phase 5 rules catalog.

## Phase 5 — diagnostic correlation

**Objective:** combine evidence into a small, explainable catalog of findings with honest certainty and scope.

Concrete tasks:

1. Version deterministic rule functions and their declared required sources/coverage. Inputs are immutable observations; no hidden IO or mutation.
2. Expand early findings: expected listener absent with service stopped; restart near a listener gap; loopback/wrong-port bind against expectation; interface/profile mismatch; matching WFP block with candidate-policy explanation; route/DNS anomalies when relevant context is known.
3. Separate “observed service stopped” from “service stopped caused missing listener”; separate direct block evidence from friendly-rule or application-transaction attribution. Report alternative explanations and required next checks.
4. Rank a concise findings summary by user relevance, severity, recency and evidence class. Show exact rule/evidence references and assumptions in expanded detail. Expire/recompute findings when evidence changes; retain historical findings with their original policy version.

**Dependencies:** source-specific availability, earlier findings/evidence model; Phase 4 required only for rules claiming direct block evidence. Some rules can ship after Phases 2–3.

**Risks:** overconfidence, contradictory snapshots, stale conclusions, an ever-growing rules catalog obscuring the table. “Unexpected” requires a saved/user expectation; a disconnected isolated IFC network is not inherently misconfigured.

**Acceptance criteria:** every finding is reproducible from stored normalized inputs and evaluator version; unavailable data prevents unsupported conclusions; inferred findings identify assumptions; Confirmed Failure requires direct failure evidence. The representative IFC8 mismatch and blocked-attempt scenarios show different certainty. Findings link to retained evidence or clearly report its expiry.

**Automated tests:** golden scenario fixtures for all finding classes, stale/contradictory evidence, unsupported conditions, ambiguous associations and clock changes; counterexamples asserting no false confirmed block; deterministic replay across input ordering; finding invalidation and evidence lifetime. Include service-hosted executable allow case as a permanent regression fixture.

**Windows verification:** scripted lab scenarios with known expected results, reviewed by a network troubleshooter; compare conclusions against event evidence rather than just whether a connection eventually succeeded. Review false positives on a VPN/multihomed workstation and a production-like server without modifying production settings.

**Effort/usefulness:** M–L; useful in increments as individual rules meet their evidence requirements.

## Phase 6 — advanced capabilities

**Objective:** make repeat investigations reusable and shareable after core correctness is established.

Concrete tasks:

1. Versioned saved filters/views and expected service/endpoint profiles. Keep customer/environment values local and editable; document parser version/migrations.
2. Manual immutable snapshots and before/after comparisons including process generations, network/policy versions, capabilities and sample gaps. Add persistence only for a demonstrated need with quota/retention controls.
3. Export preview and consistently redacted reports with findings/evidence references and explicit unsupported coverage. Raw sensitive fields require deliberate inclusion; no automatic upload.
4. Optional targeted ETW/capture only against an established gap; explicit duration/size/payload constraints and owned-session cleanup. Do not turn this into a general packet analyzer.
5. Optional AI-assisted wording only after redaction/consent and evidence references exist. No model-driven firewall verdicts, automatic repair commands or unexplained certainty upgrades; offline deterministic diagnosis remains complete.

**Dependencies:** stable schemas, evidence retention, privacy design and preceding collector validation. AI/capture are independently deferrable and not necessary for roadmap success.

**Risks:** sensitive export content, parser/schema compatibility, excessive persistent storage, untrusted imported data or AI text, capture/session complexity, expectation drift.

**Acceptance criteria:** profiles round-trip/version-migrate; snapshot diff distinguishes new process from same PID; a redacted export contains no excluded field in either facts, findings or embedded strings; imports have size/schema limits and execute nothing. Optional network/external activity is explicit. Workbench functionality remains available with capture/AI disabled.

**Automated tests:** serialization/migration and malformed/oversized input; diff fixtures across hosts/boots/policy versions; redaction of command lines, paths, SIDs, IPs, customer names and raw XML fragments; quota eviction; offline behavior; capture ownership; AI output cannot create/alter evidence classifications.

**Windows verification:** sanitized report reviewed by a second troubleshooter; repeated saved IFC8 investigations across restart; prolonged retention/export size checks; offline deployment; capture cleanup where implemented; inspect actual outbound content before any external AI test.

**Effort/usefulness:** M per reports/profile/snapshot workflow, L for optional capture/AI. Each can ship separately.

## Minimum viable expansion

Deliver Phase 1, the selected process/path/service pane from Phase 2, and a constrained Phase 3 path/port/protocol/profile/static-remote-scope evaluator with the required network context. Reuse a small evidence/finding model from the outset. Do not require WFP capture, Security audit setup, command-line inspection, persistent storage or AI.

Demo in a disposable lab: an IFC8-named test listener runs on `0.0.0.0:5001`; actual ingress interface is Domain; effective program allow rule is scoped to another remote subnet. Selecting the row and supplying the peer IP produces **Inferred: this rule does not cover this peer**, with evidence for program/port/profile matches and remote-scope mismatch. Running the same listener as a service with service Any must preserve program matching. Show **block evidence unavailable/not collected** rather than an unsupported blocked claim. Optionally read an existing 5157 later to demonstrate the separate Confirmed Failure class.

This proves cross-source diagnostic value with the current table and a small details pane. Do not label it a comprehensive firewall evaluator.

## Shared verification gates

Proposed reference gates, to calibrate on agreed hardware before adoption:

- At 1,000 and 10,000 synthetic rows, filter/sort/select interaction feedback p95 below 100 ms excluding the deliberate 250 ms debounce; target p95 below 400 ms from last typed character to filtered display. Slow heavy jobs must not delay input/window handling. Measure rather than assume the custom table is the bottleneck.
- Inventory timer remains configured at five seconds when enabled. Collectors never overlap; missed ticks and collection durations are visible. If enumeration exceeds the interval, skip/coalesce rather than queue unlimited work.
- Eight-hour monitoring/rapid-churn soak reaches a retention plateau within configured record/byte limits, with no sustained handle/session/thread growth. Record idle and active CPU, private bytes, collection duration and dropped-event counts; do not invent a universal CPU/RAM limit before measurement.
- Normal-user, elevated and hardened/delegated contexts each produce accurate capability reports. No administrator requirement for basic inventory. Every advertised OS/API feature has a documented fallback or Unavailable state.
- Default diagnosis produces no firewall/service/network/audit setting differences before/after. Validate settings read-only; never auto-enable collection to make a test pass. Any later mutation subfeature needs its own authorization and cleanup gate.

Candidate endpoint matrix to approve before implementation: Windows 11 desktop; supported Windows 10 enterprise/servicing configurations if required; Windows Server 2019/2022/2025 with Desktop Experience, extending to Server 2016 only for a demonstrated deployment need. This is a proposed test matrix, not a claim of current app or vendor support. Include a standalone host, domain/GPO server, multihomed/VPN system, standard user, restricted ACLs, protected process, IPv6/link-local, large connection count, and MDM/third-party filtering only when advertised. Server Core/remote fleet administration are outside the GUI baseline.

Maintain sanitized fixture provenance and record actual OS build, app commit, dependency lock, privileges, audit state, policy store version and test traffic timestamps. Tests requiring policy/service changes run only on authorized disposable endpoints. Current audit execution did not run these tests or alter endpoint settings.
