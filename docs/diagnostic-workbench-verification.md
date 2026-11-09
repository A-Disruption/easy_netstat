# Implementation verification

Date: 2026-11-08. Branch: `codex/diagnostic-workbench`. Baseline/master commit: `02c1aa90882bcdf37191126503a2d6fc4624c135`.

## Completed automated checks

| Check | Result |
| --- | --- |
| `cargo test --locked --offline --no-fail-fast` | **67 passed**, 0 failed, 0 ignored: 50 library tests, 15 application/filter tests, 2 Windows integration tests |
| `cargo clippy --locked --offline --all-targets --no-deps -- -D warnings` | Passed |
| `cargo fmt --package easy_netstat -- --check` | Passed |
| `cargo build --locked --offline --release` | Passed; executable at `target/release/easy_netstat.exe` |
| `git diff --check` | Passed |
| Documentation cross-links | Checked |
| Sibling UI working trees | All three clean; tested revisions recorded in implementation notes |
| Master branch | Remained at the original baseline commit |

Compiler: Rust 1.99.0 (`b940084d7`), Cargo 1.99.0. All dependency resolution/build checks used the existing local cache, without dependency downloads. The manifest's 1.95 minimum was not separately compiled with a 1.95 toolchain.

The Windows integration checks successfully enumerated temporary owned IPv4/IPv6 TCP/UDP endpoints and exercised the on-demand collector. The read-access context returned process/service/network/route information and readable firewall categories. Port/address/interface-related firewall filter reads were denied, so the collector preserved the other categories and reported **Partial** policy. Audit-policy inspection was unavailable, and no matching WFP Security records were present. These outcomes validate graceful degradation, not successful privileged collection. The nonexistent-filter WFP test validates error/denied-access handling without changing filters.

Process enrichment revalidated native creation identity despite CIM timestamp rounding. Timeout/cancellation tests passed; a dedicated test verified an owned descendant process does not survive normal collector completion. Tests bind temporary loopback sockets, create/remove temporary test files and start/terminate owned hidden test processes; none changes firewall rules, audit policy, service state or network settings.

## Remaining user acceptance work

The [consolidated testing guide](diagnostic-workbench-testing.md) covers the final manual pass. Rendered GUI interaction, actual IFC8/enterprise application behavior, privileged/GPO/MDM policy combinations, real corresponding 5152/5157 block attribution, service restart/crash scenarios, all target Windows versions and an eight-hour production-like soak have not been certified by the automated checks. The 10,000-row construction test is not a p95 GUI latency benchmark.

Optional capture/subscription collectors, audit-setting mutation/recovery and external AI are deliberately not enabled or implemented; see [implementation scope](diagnostic-workbench-implementation.md). Native Win32 calls may complete after cancellation; their results are discarded and they do not execute on the UI thread.

## Diagnostics popup revision — 2026-11-09

Diagnostics now uses the same themed modal component as Settings. The table remains full width; selection is separate from opening Diagnostics. Tabs expose Overview, Firewall rules, Process / services, Network, Events, History, and Tools / reports. The firewall tab shows profiles/default policies, explicit collection gaps, a searchable paged list of all collected rules, a candidate-only scope and full selected-rule predicates/provenance independently of completed scenario analysis.

Verification for this revision:

- **73 tests passed**, 0 failed, 0 ignored: 50 library, 21 application/filter/UI, 2 Windows integration tests.
- Six new tests cover popup/settings exclusivity and dismissal/cancellation, selection without forced popup opening, raw rules visible before analysis, multi-field search, paging/tab construction with partial/missing data, and unavailable predicates distinguished from Any.
- Strict Clippy, package formatting, diff whitespace checks and the locked offline release build passed.
- The rendered-window check through the computer-use skill could not launch the application because app approval timed out. No visual layout verification is claimed; the automated tests exercise state transitions and widget construction, not rendered geometry.

The release executable remains `target/release/easy_netstat.exe`. Firewall collection and diagnostic certainty rules were not changed by this UI revision.


## Popup sizing and visual hierarchy — 2026-11-09

- **76 tests passed**, 0 failed, 0 ignored: 50 library, 24 application/filter/UI, 2 Windows integration tests.
- New headless layout regression uses the same expanding-body helper as the modal with an actual scrollable child. Growing from 900×400 to 1100×650 adds exactly 250 pixels to the scroll viewport, leaves fixed header/footer heights intact, and shrinking to 760×300 reduces the viewport accordingly.
- New semantic tests keep configuration mismatches distinct from confirmed failures and unknown predicates distinct from matches. Theme tests cover Light, Dark and Nord palettes and distinguish evidence/status surfaces.
- Strict Clippy, package formatting, diff whitespace checks and locked offline release build passed. Sandbox hard-link cache warnings only affected incremental cache copying.
- No rendered-window inspection was performed for this revision. The consolidated manual guide now includes resizing, light/dark readability, section grouping and color-independent status labels. Automated geometry/palette checks do not certify rendered text wrapping or accessibility contrast.

The release executable is `target/release/easy_netstat.exe`. All work remains on `codex/diagnostic-workbench`; master is unchanged. No collector or firewall-evaluation behavior changed.


## Reserved scrollbar space — 2026-11-09

The shared diagnostic scroll area now uses Iced's embedded scrollbar layout (`spacing(8)`) instead of its default floating rail. When content overflows, layout reserves the default 10-pixel rail plus an 8-pixel gap; otherwise content gets the full width. This applies to every diagnostic tab without changing the popup's scroll identity or vertical expansion.

**77 tests passed** (50 library, 25 application/UI, 2 Windows integration), with no failures or ignored tests. The new headless layout regression checks the content's right edge at narrow/wide widths and across scrollbar appearance, disappearance and reappearance. The existing vertical-resize regression now also uses this shared scroll-area builder. Strict Clippy, formatting, whitespace checks and the locked offline release build passed. Rendered-window inspection remains part of the final user acceptance pass.
