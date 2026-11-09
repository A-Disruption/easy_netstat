# Easy Netstat — Windows Network Diagnostic Workbench

A searchable TCP/UDP IPv4/IPv6 connection table with optional, read-only diagnostics. The table remains the primary interface. Automatic refresh starts paused; enable it in Settings (five seconds initially, configurable from 1–3600 seconds). Manual refresh works while paused.

Select a row and click **Diagnostics** to open a settings-style popup with tabs for Overview, Firewall rules, Process / services, Network, Events, History, and Tools / reports. The connection table keeps its full width; selecting a row does not force the popup open. Expensive collection and evaluation run in background jobs. Nothing enables auditing, changes rules, starts/stops services, or changes network configuration.

## Using diagnostics

1. Select a connection and click **Diagnostics**. Review its process path and creation identity in **Process / services**.
2. For a listener, replace the wildcard local address with the actual local IP:port and supply a peer IP:port when known. Set the examined direction; it is an assumption, not inferred from port numbers. IPv6 endpoints use `[address%scope]:port`.
3. Enter an interface alias or let a unique concrete local address identify it. Optional service/port inputs describe your expectations; an assumed service is not proof of socket ownership.
4. Click **Collect diagnostics**. The owned PowerShell collection has a 90-second deadline and Cancel action. Native OS calls, including subsequent filter metadata lookups, may finish later; late/cancelled results are discarded and never block the UI. Firewall configuration is cached for 60 seconds; **Refresh policy** in Firewall rules bypasses that cache. Changing scenario inputs clears findings; **Evaluate collected evidence** in Overview reruns analysis without querying Windows.
5. Open **Firewall rules** to browse/search all collected rules, even before a scenario can be evaluated. Switch to **Examined candidates** for analyzed rules. Select a rule to see its program, service restriction, protocol, local/remote ports and addresses, profiles, interfaces, policy source, enforcement and condition results. Profiles/default policies and collection gaps appear directly above the browser.
6. Use the other tabs for services, interfaces/DNS/routes, recorded WFP events/filter metadata and history. Saved views, snapshots, DNS lookup and report preview/export are in **Tools / reports**. Close the popup with its title-bar close button, Escape or the backdrop.

The popup content expands with its height. Overview presents summary counts and finding cards before the traffic inputs; each finding separates the explanation from its next check. Theme-aware badges distinguish observed facts (blue), inferred findings or limited data (amber), and confirmed failures (red). Neutral grouped fields and subdued labels keep supporting detail readable. Rule-condition matches use green, without claiming that traffic passed.

**Observed** means a returned OS fact. **Inferred** means a conclusion with assumptions and limitations. **Confirmed Failure** requires a matching recorded WFP failure plus revalidated process lifetime and tuple/direction. A missing allow candidate never confirms a block. A matching program rule remains valid for analysis when its executable runs as a service; service restrictions are checked separately.

Standard users can use inventory. Individual firewall filter/audit/event/process queries can require additional permissions; readable categories remain available when others fail. Source availability is shown within each relevant tab. No records, denied access and incomplete collection are distinct; missing rule predicates are labeled **Unavailable / not collected**, never assumed to be Any.

## Filtering

Examples:

```text
proc:IFC8 port:5001
proto:tcp state:Listen
(proc:IFC8 | proc:agent) !local:127.0.0.1
proc:"Acme Agent.exe"
```

Fields: `protocol/proto`, `process/proc`, `state`, `local/localaddr`, `remote/remoteaddr`, `pid`, `port`, or unqualified text. Matching ignores case. Plain values are substrings; quoted values without edge wildcards are exact. Leading/trailing `*` supports suffix/prefix/contains matching; interior `*` is literal. Numeric `port:` is exact on either endpoint. Spaces normally mean AND, but repeated direct criteria for one field are OR alternatives, preserving the original application behavior. Invalid input leaves the last valid filter applied and displays an error. Autocomplete supports quoted process names and field values.

## Local data and privacy

Saved views live in `%LOCALAPPDATA%\EasyNetstat\views.json` and may contain customer/endpoint context. History is in memory: up to 50,000 change records/32 MiB accounted record data, with a 15-minute age window pruned on successful collection. No unbounded archive or background upload exists.

Reports use an allowlist and anonymous evidence/candidate references. Preview before export. Command lines, usernames, addresses, paths, rule names and raw events are omitted. Full snapshot JSON is deliberately separate and contains addresses, process paths, and any collected policy/network configuration; protect it as sensitive local diagnostic data. Exports never overwrite existing files. Imported snapshots are only used for comparison and cannot execute collectors or commands.

DNS resolution is an explicit optional network action with a 10-second deadline. Packet capture, automatic audit setup, AI/network uploads, firewall management and service control are not enabled.

## Build and test

Requires Windows desktop tooling, Rust (tested with 1.99.0; dependency MSRV 1.95), and these sibling source checkouts:

```text
Rust Projects/
  easy_netstat/
  widgets/
  advanced-table/
  iced-window-decorations/
```

`Cargo.lock` is tracked and Iced is pinned to an exact revision. The three local UI dependencies still require compatible sibling sources; they are not vendored or fully locked by Cargo. Generated icon/font assets are checked in; ordinary builds do not regenerate source or contact Fontello.

```powershell
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets --no-deps -- -D warnings
cargo fmt --package easy_netstat -- --check
```

Use `--offline` when dependencies are already cached. Windows integration tests open temporary loopback TCP/UDP sockets and query existing OS state. They never alter firewall/audit/service configuration. An OS sandbox that denies IP Helper or file replacement can prevent those tests from exercising the endpoint; run them in an ordinary development shell. Do not use `cargo fmt --all` to reformat external sibling repositories.

See [implementation notes](docs/diagnostic-workbench-implementation.md) and the [consolidated Windows test guide](docs/diagnostic-workbench-testing.md). The five original audit documents describe baseline commit `02c1aa9`, before this implementation.
