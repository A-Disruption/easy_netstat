# Fixed, read-only collector. Request data arrives on stdin, never in command text.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$caps = New-Object System.Collections.Generic.List[object]
function Status($source, $state, $detail) {
    $caps.Add([ordered]@{ source = $source; status = $state; detail = $detail })
}
function Strings($value) {
    @($value | ForEach-Object { if ($null -ne $_) { [string]$_ } })
}
function Map($command) {
    $result = @{}
    try {
        & $command -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object { $result[[string]$_.InstanceID] = $_ }
        Status $command 'Available' 'Associated filters read from ActiveStore.'
    } catch { Status $command 'Unavailable' $_.Exception.Message }
    return ,$result
}
$started = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$services = @(); $interfaces = @(); $routes = @(); $events = @(); $process = $null
$policy = [ordered]@{ collected_ms = 0; version = ''; profiles = @(); rules = @(); complete = $false }
try {
    $target = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [uint32]$request.pid)
    if ($target) {
        $ownerResult = Invoke-CimMethod -InputObject $target -MethodName GetOwner -ErrorAction SilentlyContinue
        $owner = $null
        if ($ownerResult -and $ownerResult.ReturnValue -eq 0) { $owner = $ownerResult.Domain + '\' + $ownerResult.User }
        $process = [ordered]@{ pid = [uint32]$target.ProcessId; created = [uint64]$target.CreationDate.ToFileTimeUtc(); command_line = $target.CommandLine; owner = $owner; path = $target.ExecutablePath }
        Status 'Process' 'Available' 'On-demand process details; identity must match the selected creation time.'
    } else { Status 'Process' 'Unavailable' 'Process exited or is not visible.' }
} catch { Status 'Process' 'Unavailable' $_.Exception.Message }
try {
    $serviceQuery = @(Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq [uint32]$request.pid -or ($request.expected_service -and $_.Name -eq $request.expected_service) })
    $services = @($serviceQuery | ForEach-Object {
        [ordered]@{ name = $_.Name; display_name = $_.DisplayName; pid = [uint32]$_.ProcessId; state = [string]$_.State; start_mode = [string]$_.StartMode; account = [string]$_.StartName; binary = [string]$_.PathName }
    })
    Status 'Services' 'Available' 'Visible services only; shared PID association is not socket-level attribution.'
} catch { Status 'Services' 'Unavailable' $_.Exception.Message }
try {
    $profiles = @(Get-NetConnectionProfile)
    $configs = @(Get-NetIPConfiguration -All)
    $adapters = @(Get-NetAdapter -IncludeHidden)
    $interfaces = @($configs | Select-Object -First 256 | ForEach-Object {
        $config = $_; $adapter = $adapters | Where-Object { $_.ifIndex -eq $config.InterfaceIndex } | Select-Object -First 1
        $profile = $profiles | Where-Object { $_.InterfaceIndex -eq $config.InterfaceIndex } | Select-Object -First 1
        $category = [string]$profile.NetworkCategory
        if ($category -eq 'DomainAuthenticated') { $category = 'Domain' }
        $kind = ''
        if ($adapter.InterfaceType -eq 6) { $kind = 'Wired' }
        elseif ($adapter.InterfaceType -eq 71) { $kind = 'Wireless' }
        elseif ($adapter.InterfaceType -eq 23) { $kind = 'RemoteAccess' }
        $counters = $null
        try { $counters = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction Stop } catch {}
        $errors = $null
        if ($counters) { $errors = [uint64]$counters.ReceivedPacketErrors + [uint64]$counters.OutboundPacketErrors }
        [ordered]@{ index = [uint32]$config.InterfaceIndex; alias = [string]$config.InterfaceAlias; profile = $category; kind = $kind;
            addresses = @(@($config.IPv4Address) + @($config.IPv6Address) | Where-Object { $_ } | ForEach-Object { [string]$_.IPAddress });
            dns = @($config.DNSServer | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ });
            gateways = @(@($config.IPv4DefaultGateway) + @($config.IPv6DefaultGateway) | Where-Object { $_ } | ForEach-Object { [string]$_.NextHop });
            status = [string]$adapter.Status; errors = $errors }
    })
    Status 'Network' $(if ($configs.Count -gt 256) { 'Partial' } else { 'Available' }) 'Current adapter/profile context; counters are absolute, not attributed to this flow.'
} catch { Status 'Network' 'Unavailable' $_.Exception.Message }
try {
    $allRoutes = @(Get-NetRoute)
    $routes = @($allRoutes | Select-Object -First 4096 | ForEach-Object { [ordered]@{ destination = [string]$_.DestinationPrefix; next_hop = [string]$_.NextHop; interface = [uint32]$_.InterfaceIndex; metric = [uint32]$_.RouteMetric } })
    Status 'Routes' $(if ($allRoutes.Count -gt 4096) { 'Partial' } else { 'Available' }) 'Current configured routes; not proof of the actual historical packet path.'
} catch { Status 'Routes' 'Unavailable' $_.Exception.Message }
if ($request.include_policy) {
    try {
        $fp = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
            [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; inbound = [string]$_.DefaultInboundAction;
                outbound = [string]$_.DefaultOutboundAction; allow_inbound_rules = [string]$_.AllowInboundRules; allow_local_rules = [string]$_.AllowLocalFirewallRules }
        })
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore)
        $app = Map 'Get-NetFirewallApplicationFilter'; $svc = Map 'Get-NetFirewallServiceFilter'
        $port = Map 'Get-NetFirewallPortFilter'; $addr = Map 'Get-NetFirewallAddressFilter'
        $iface = Map 'Get-NetFirewallInterfaceFilter'; $itype = Map 'Get-NetFirewallInterfaceTypeFilter'
        $security = Map 'Get-NetFirewallSecurityFilter'
        $normalized = @($rules | Select-Object -First 20000 | ForEach-Object {
            $r = $_; $id = [string]$r.InstanceID
            $a = $app[$id]; $s = $svc[$id]; $p = $port[$id]; $d = $addr[$id]; $i = $iface[$id]; $t = $itype[$id]; $sec = $security[$id]
            $unsupported = New-Object System.Collections.Generic.List[string]
            if ($a.Package -and [string]$a.Package -ne 'Any') { $unsupported.Add('Package restriction: ' + [string]$a.Package) }
            if ($a.PolicyAppId) { $unsupported.Add('PolicyAppId: ' + [string]$a.PolicyAppId) }
            if ($r.EdgeTraversalPolicy -and [string]$r.EdgeTraversalPolicy -ne 'Block') { $unsupported.Add('Edge traversal: ' + [string]$r.EdgeTraversalPolicy) }
            foreach ($field in @('Authentication','Encryption','OverrideBlockRules','LocalUser','RemoteUser','RemoteMachine')) {
                $v = [string]$sec.$field
                if ($v -and $v -notin @('Any','NotRequired','False','NotConfigured')) { $unsupported.Add($field + ': ' + $v) }
            }
            foreach ($field in @('RemoteDynamicKeywordAddresses','PolicyAppId','Owner','Platform')) {
                $v = [string]$r.$field
                if ($v -and $v -notin @('Any','{}','0')) { $unsupported.Add($field + ': ' + $v) }
            }
            if ($r.LooseSourceMapping -eq $true -or $r.LocalOnlyMapping -eq $true) { $unsupported.Add('Special source/local mapping') }
            $programs = @(Strings $a.Program | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) })
            [ordered]@{ id = [string]$r.Name; name = [string]$r.DisplayName; source = [string]$r.PolicyStoreSource; source_type = [string]$r.PolicyStoreSourceType;
                enabled = ([string]$r.Enabled -eq 'True'); action = [string]$r.Action; direction = [string]$r.Direction;
                profiles = @(([string]$r.Profile -split ',') | ForEach-Object { $_.Trim() });
                program = $programs; service = @(Strings $s.Service); protocol = @(Strings $p.Protocol);
                local_ports = @(Strings $p.LocalPort); remote_ports = @(Strings $p.RemotePort);
                local_addresses = @(Strings $d.LocalAddress); remote_addresses = @(Strings $d.RemoteAddress);
                interfaces = @(Strings $i.InterfaceAlias); interface_types = @(Strings $t.InterfaceType);
                unsupported = @($unsupported.ToArray()); complete = [bool]($a -and $s -and $p -and $d -and $i -and $t -and $sec);
                enforcement = [string]$r.EnforcementStatus }
        })
        # Detect rule churn across the associated-filter reads. This is still
        # not an atomic OS policy snapshot; collection interval stays explicit.
        $after = @(Get-NetFirewallRule -PolicyStore ActiveStore | ForEach-Object { [string]$_.InstanceID } | Sort-Object)
        $before = @($rules | ForEach-Object { [string]$_.InstanceID } | Sort-Object)
        $consistent = (($before -join "`n") -eq ($after -join "`n"))
        $policyTime = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $policy = [ordered]@{ collected_ms = $policyTime; version = [string]$policyTime; profiles = $fp; rules = $normalized;
            complete = [bool]($consistent -and $rules.Count -le 20000 -and @($normalized | Where-Object { -not $_.complete }).Count -eq 0) }
        Status 'Firewall' $(if ($policy.complete) { 'Available' } else { 'Partial' }) 'ActiveStore with associated filters. Provider/advanced conditions may remain unsupported; multi-query collection is not atomic.'
    } catch { Status 'Firewall' 'Unavailable' $_.Exception.Message }
}
try {
    # Read existing audit configuration only; never enable events.
    $audit = & "$env:SystemRoot\System32\auditpol.exe" /get /subcategory:'{0CCE9226-69AE-11D9-BED3-505054503030},{0CCE9225-69AE-11D9-BED3-505054503030}' /r 2>&1
    if ($LASTEXITCODE -eq 0) { Status 'Audit policy' 'Available' ($audit -join "`n") }
    else { Status 'Audit policy' 'Unavailable' ($audit -join "`n") }
} catch { Status 'Audit policy' 'Unavailable' $_.Exception.Message }
try {
    $eventsFound = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(5152,5154,5155,5156,5157,5158,5159); StartTime = (Get-Date).AddMinutes(-15) } -MaxEvents 1001 -ErrorAction Stop)
    $events = @($eventsFound | Select-Object -First 1000 | ForEach-Object {
        [ordered]@{ channel = [string]$_.LogName; provider = [string]$_.ProviderName; record_id = [uint64]$_.RecordId; event_id = [uint32]$_.Id;
            time_ms = ([DateTimeOffset]$_.TimeCreated.ToUniversalTime()).ToUnixTimeMilliseconds(); xml = $_.ToXml() }
    })
    Status 'WFP Security events' $(if ($eventsFound.Count -gt 1000) { 'Partial' } else { 'Available' }) 'Existing events only, last 15 minutes, newest 1000 globally; absence is not proof of no block. Provider-side auditing may be disabled.'
} catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { Status 'WFP Security events' 'No records' 'No matching records; inspect audit settings before drawing conclusions.' }
    else { Status 'WFP Security events' 'Unavailable' $_.Exception.Message }
}
foreach ($log in @('System','Application')) {
    try {
        $providers = if ($log -eq 'System') { @('Service Control Manager') } else { @('Application Error','Windows Error Reporting') }
        $recent = @(Get-WinEvent -FilterHashtable @{ LogName = $log; ProviderName = $providers; StartTime = (Get-Date).AddMinutes(-15) } -MaxEvents 101 -ErrorAction Stop)
        $events += @($recent | Select-Object -First 100 | ForEach-Object {
            [ordered]@{ channel = [string]$_.LogName; provider = [string]$_.ProviderName; record_id = [uint64]$_.RecordId; event_id = [uint32]$_.Id;
                time_ms = ([DateTimeOffset]$_.TimeCreated.ToUniversalTime()).ToUnixTimeMilliseconds(); xml = $_.ToXml() }
        })
        Status ($log + ' context events') $(if ($recent.Count -gt 100) { 'Partial' } else { 'Available' }) 'Newest 100 provider events; attribution is evaluated from structured identity fields.'
    } catch {
        Status ($log + ' context events') $(if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { 'No records' } else { 'Unavailable' }) $_.Exception.Message
    }
}
[ordered]@{ schema = 1; started_ms = $started; finished_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();
    process = $process; services = $services; interfaces = $interfaces; routes = $routes; policy = $policy; events = $events; capabilities = @($caps.ToArray()) } | ConvertTo-Json -Depth 12 -Compress
