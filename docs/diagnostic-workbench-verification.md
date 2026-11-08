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
