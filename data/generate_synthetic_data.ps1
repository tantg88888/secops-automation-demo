param([string]$OutDir)
# Synthetic data for the secops-automation-demo repo.
# Fictitious "Example Insurance Group" (corp.example.com). No real client data.
# Deliberately reproduces data problems seen in real scanner/directory exports.
$ErrorActionPreference = 'Stop'
$rng = New-Object System.Random 20261024
function Pick($arr) { $arr[$rng.Next($arr.Count)] }
function Csv($rows, $name) { $rows | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $OutDir $name); "{0}: {1} rows" -f $name, @($rows).Count }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$inv = [Globalization.CultureInfo]::InvariantCulture

# ---------------- CMDB ----------------
$entities = 'EIG-SG','EIG-LIFE','EIG-GEN'
$roles = 'app','db','web','file','dc','mq','jump'
$cmdb = @()
for ($i = 1; $i -le 60; $i++) {
    $ent = $entities[($i - 1) % 3]
    $role = Pick $roles
    $short = ('{0}-{1}-{2:D3}' -f ($ent -replace 'EIG-', '').ToLower(), $role, $i)
    $cmdb += [pscustomobject]@{
        asset_id    = 'CI{0:D5}' -f (1000 + $i)
        hostname    = "$short.corp.example.com"
        ip_address  = '10.{0}.{1}.{2}' -f (10 + [array]::IndexOf($entities, $ent)), $rng.Next(1, 20), $rng.Next(2, 250)
        entity      = $ent
        os          = Pick @('Windows Server 2019', 'Windows Server 2022', 'RHEL 8', 'RHEL 9', 'Ubuntu 22.04')
        environment = Pick @('PROD', 'PROD', 'PROD', 'UAT', 'DEV')
        criticality = Pick @('High', 'Medium', 'Medium', 'Low')
        owner_team  = Pick @('Infra-Windows', 'Infra-Linux', 'App-Support', 'DBA')
    }
}
Csv $cmdb 'cmdb_assets.csv'

# ---------------- Vulnerability catalogue (made-up plugin ids) ----------------
$noFix = 'There is no known solution at this time.'
$catalog = @(
    @(900101, 'OpenSSL 3.0.x < 3.0.14 Multiple Vulnerabilities', 'High', 'Upgrade OpenSSL to 3.0.14 or later.'),
    @(900102, 'OpenSSL 3.0.x < 3.0.15 Denial of Service', 'Medium', 'Upgrade OpenSSL to 3.0.15 or later.'),
    @(900110, 'SSL Certificate Cannot Be Trusted', 'Medium', 'Purchase or generate a proper certificate.'),
    @(900111, 'SSL Self-Signed Certificate', 'Medium', 'Purchase or generate a proper certificate.'),
    @(900112, 'TLS Version 1.0 Protocol Detection', 'Medium', 'Enable TLS 1.2 or later and disable TLS 1.0.'),
    @(900113, 'SSL Medium Strength Cipher Suites Supported', 'Medium', 'Reconfigure the service to avoid medium strength ciphers.'),
    @(900120, 'Microsoft Windows Security Update (Monthly Rollup)', 'Critical', 'Apply the latest cumulative update.'),
    @(900121, 'Microsoft .NET Framework Security Update', 'High', 'Apply the vendor security update.'),
    @(900122, 'SMB Signing not required', 'Medium', 'Enforce message signing in the host configuration.'),
    @(900130, 'Apache Tomcat 9.0.x < 9.0.90 Multiple Vulnerabilities', 'High', 'Upgrade Apache Tomcat to 9.0.90 or later.'),
    @(900131, 'Apache HTTP Server < 2.4.60 Multiple Vulnerabilities', 'Critical', 'Upgrade Apache HTTP Server to 2.4.60 or later.'),
    @(900140, 'RHEL 8 : kernel security update', 'High', 'Update the affected kernel packages.'),
    @(900141, 'RHEL 9 : glibc security update', 'Medium', 'Update the affected glibc packages.'),
    @(900142, 'Ubuntu 22.04 : OpenSSH vulnerability', 'Medium', 'Update the affected openssh packages.'),
    @(900150, 'Microsoft SQL Server Unsupported Version Detection', 'Critical', 'Upgrade to a supported version.'),
    @(900151, 'Oracle Java SE Multiple Vulnerabilities', 'High', 'Upgrade to the latest Java SE update.'),
    @(900160, 'SSH Weak Key Exchange Algorithms Enabled', 'Low', 'Disable the weak algorithms.'),
    @(900161, 'ICMP Timestamp Request Remote Date Disclosure', 'Low', 'Filter out ICMP timestamp requests.'),
    @(900170, 'Linux Kernel Speculative Execution Side Channel', 'Medium', $noFix),
    @(900171, 'Intel CPU Microcode Information Disclosure', 'Medium', $noFix),
    @(900172, 'TCP Timestamps Information Disclosure', 'Low', $noFix),
    @(900180, 'VMware Tools Multiple Vulnerabilities', 'High', 'Upgrade VMware Tools to the latest version.')
)
$ports = @{ 900110 = 443; 900111 = 443; 900112 = 443; 900113 = 636; 900122 = 445; 900130 = 8080; 900131 = 443; 900150 = 1433; 900160 = 22; 900142 = 22 }

# Severity "recast": vendor severity kept, reported severity downgraded to Info when there is no fix
function New-Finding($asset, $c, [datetime]$first, [datetime]$last, [string]$nameStyle) {
    $plug = $c[0]; $vendorSev = $c[2]; $sol = $c[3]
    $sev = if ($sol -eq $noFix) { 'Info' } else { $vendorSev }
    $port = if ($ports.ContainsKey($plug)) { $ports[$plug] } else { 0 }
    $nm = switch ($nameStyle) { 'short' { $asset.hostname.Split('.')[0].ToUpper() } 'ip' { $asset.ip_address } default { $asset.hostname } }
    [pscustomobject]@{
        finding_id        = [guid]::NewGuid().ToString()
        asset_name        = $nm
        ipv4              = $asset.ip_address
        plugin_id         = $plug
        plugin_name       = $c[1]
        severity          = $sev
        vendor_severity   = $vendorSev
        port              = $port
        protocol          = if ($port -eq 0) { '' } else { 'tcp' }
        first_seen        = $first.ToString('yyyy-MM-dd')
        last_seen         = $last.ToString('yyyy-MM-dd')
        solution          = $sol
    }
}
function NameStyle { $r = $rng.NextDouble(); if ($r -lt 0.15) { 'short' } elseif ($r -lt 0.2) { 'ip' } else { 'fqdn' } }

# Assets scanned: 55 of the CMDB plus 3 hosts unknown to the CMDB
$unknown = 1..3 | ForEach-Object { [pscustomobject]@{ hostname = ('legacy-srv-{0:D2}.corp.example.com' -f $_); ip_address = ('10.99.0.{0}' -f (10 + $_)) } }
$scanned = @($cmdb | Select-Object -First 55) + $unknown

# ---------------- Q2 scan (end June) ----------------
$q2 = @(); $q2Keys = @()
foreach ($a in $scanned) {
    $style = NameStyle
    $n = $rng.Next(6, 16)
    $chosen = $catalog | Sort-Object { $rng.Next() } | Select-Object -First $n
    foreach ($c in $chosen) {
        $first = (Get-Date '2025-09-01').AddDays($rng.Next(0, 250))
        $f = New-Finding $a $c $first (Get-Date '2026-06-26') $style
        $q2 += $f; $q2Keys += ,@($a, $c, $first, $style)
        # ~7%: scanner re-keyed the asset, older duplicate record for the same finding
        if ($rng.NextDouble() -lt 0.07) { $q2 += New-Finding $a $c $first (Get-Date '2026-03-30').AddDays($rng.Next(0, 25)) $style }
    }
}
Csv $q2 'scan_2026Q2.csv'

# ---------------- Q3 scan (end Sept): new finding_ids for persisting findings ----------------
$q3 = @()
foreach ($k in $q2Keys) {
    if ($rng.NextDouble() -lt 0.68) { $q3 += New-Finding $k[0] $k[1] $k[2] (Get-Date '2026-09-22') $k[3] }   # persists (new id!)
}
foreach ($a in $scanned) {                                                                                     # new findings
    $chosen = $catalog | Sort-Object { $rng.Next() } | Select-Object -First $rng.Next(0, 4)
    foreach ($c in $chosen) { $q3 += New-Finding $a $c (Get-Date '2026-07-01').AddDays($rng.Next(0, 80)) (Get-Date '2026-09-22') 'fqdn' }
}
# drop exact asset|plugin|port repeats created by the random "new" picks
$q3 = $q3 | Group-Object asset_name, plugin_id, port | ForEach-Object { $_.Group[0] }
Csv $q3 'scan_2026Q3.csv'

# ---------------- Ad-hoc rescan of 2 assets after patching: local checks only (port 0) ----------------
$adhocAssets = $cmdb[3], $cmdb[4]
$adhoc = @()
foreach ($k in $q2Keys | Where-Object { $_[0] -in $adhocAssets }) {
    $port = if ($ports.ContainsKey($k[1][0])) { $ports[$k[1][0]] } else { 0 }
    if ($port -eq 0 -and $rng.NextDouble() -lt 0.4) { $f = New-Finding $k[0] $k[1] $k[2] (Get-Date '2026-08-14') 'fqdn'; $adhoc += $f }   # still open
}
Csv $adhoc 'scan_adhoc_2026-08-14.csv'

# ---------------- Directory: on-prem AD and cloud (Entra) ----------------
$first = 'Alex','Ben','Chloe','Daniel','Elaine','Farid','Grace','Hui Min','Irfan','Jia Hui','Kumar','Li Wei','Mei Ling','Nur','Oliver','Priya','Qian','Rachel','Sanjay','Ting','Umar','Vivian','Wei Jie','Xin Yi','Yusof','Zhi Hao'
$last  = 'Tan','Lim','Lee','Ng','Ong','Wong','Goh','Chua','Koh','Teo','Rahman','Singh','Kumar','Chen','Ho'
$depts = 'Finance','Claims','Underwriting','IT','HR','Actuarial','Sales','Compliance'
$asOfAd = Get-Date '2026-09-21'; $asOfEntra = Get-Date '2026-09-17'
$people = @()
for ($i = 1; $i -le 220; $i++) {
    $fn = Pick $first; $ln = Pick $last
    $upn = ('{0}.{1}{2}@corp.example.com' -f ($fn -replace ' ', '').ToLower(), $ln.ToLower(), $i)
    $people += [pscustomobject]@{ upn = $upn; name = "$fn $ln"; dept = Pick $depts; ent = Pick $entities }
}
$managers = $people | Select-Object -First 15
$ad = @(); $entra = @()
$i = 0
foreach ($p in $people) {
    $i++
    $mgr = Pick $managers
    $created = $asOfAd.AddDays(-$rng.Next(30, 3000))
    $lastLogon = if ($rng.NextDouble() -lt 0.08) { $null } else { $asOfAd.AddDays(-[int][math]::Pow($rng.NextDouble(), 3) * 400) }
    $enabled = $rng.NextDouble() -gt 0.06
    $svc = if ($i % 37 -eq 0) { 'Yes' } else { '' }          # blank means No
    $admin = if ($i % 29 -eq 0) { 'Domain Admins' } elseif ($i % 11 -eq 0) { 'Server Operators' } else { '' }
    $inAd = $i -le 200                                        # 20 cloud-only accounts
    $inEntra = ($i % 25 -ne 0)                                # some AD-only accounts
    if ($inAd) {
        $ad += [pscustomobject]@{
            UserPrincipalName = $p.upn
            DisplayName       = $p.name
            Department        = $p.dept
            Company           = $p.ent
            ManagerName       = 'XXXXX XXXXX'                 # masked in the source extract
            ManagerEmail      = $mgr.upn
            Enabled           = $enabled
            ServiceAccount    = $svc
            PrivilegedGroups  = $admin
            # stored day-first although the column is read as month-first downstream
            WhenCreated       = $created.ToString('dd/MM/yyyy', $inv)
            LastLogonDate     = if ($lastLogon) { $lastLogon.ToString('dd/MM/yyyy', $inv) } else { '' }
            PasswordNeverExpires = ($svc -eq 'Yes') -or ($rng.NextDouble() -lt 0.03)
        }
    }
    if ($inEntra) {
        $sign = if ($lastLogon) { $lastLogon.AddDays($rng.Next(-5, 5)) } else { $null }
        $entra += [pscustomobject]@{
            userPrincipalName      = $p.upn
            displayName            = $p.name
            accountEnabled         = if ($inAd) { $enabled } else { $rng.NextDouble() -gt 0.1 }
            userType               = if ($inAd -or $rng.NextDouble() -lt 0.5) { 'Member' } else { 'Guest' }
            onPremisesSyncEnabled  = $inAd
            createdDateTime        = $created.ToString('yyyy-MM-ddTHH:mm:ssZ')
            lastSignInDateTime     = if ($sign -and $sign -le $asOfEntra) { $sign.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }
            mfaRegistered          = $rng.NextDouble() -gt 0.12
            assignedLicenses       = Pick @('M365 E3', 'M365 E3', 'M365 E5', 'None')
        }
    }
}
Csv $ad 'ad_users_onprem.csv'
Csv $entra 'entra_accounts.csv'
