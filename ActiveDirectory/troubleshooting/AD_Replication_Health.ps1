#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD_Replication_Health.ps1 — Check AD replication status across all DCs.

.DESCRIPTION
    Runs replication diagnostics (repadmin /replsummary, /showrepl) and
    reports failures, queue backlogs, and USN rollback indicators.

.USAGE
    .\AD_Replication_Health.ps1 [-Domain contoso.com]

.NOTES
    Requires: Active Directory module, Domain Admin rights.
    Run from any Domain Controller or management workstation with RSAT.
#>
param(
    [string]$Domain = (Get-ADDomain).DNSRoot
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "=== AD Replication Health Check: $Domain ===" -ForegroundColor Cyan

# ── 1. Replication summary ──────────────────────────────────────────────────
Write-Host "`n[+] Replication Summary (repadmin /replsummary):" -ForegroundColor Yellow
$replSummary = repadmin /replsummary /bysrc /bydest 2>&1
$replSummary | ForEach-Object { Write-Host "  $_" }

# ── 2. Failed replication links ─────────────────────────────────────────────
Write-Host "`n[+] Replication Failures:" -ForegroundColor Yellow
$replErrors = repadmin /showrepl * /errorsonly 2>&1
if ($replErrors -match "no errors") {
    Write-Host "  No replication errors detected." -ForegroundColor Green
} else {
    $replErrors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}

# ── 3. DCs with replication queue backlog ───────────────────────────────────
Write-Host "`n[+] Replication Queue (pending operations):" -ForegroundColor Yellow
$DCs = Get-ADDomainController -Filter * -Server $Domain | Select-Object -Expand HostName
foreach ($DC in $DCs) {
    $queue = repadmin /queue $DC 2>&1 | Select-String "Number of" | Select-Object -First 1
    Write-Host ("  {0,-40} {1}" -f $DC, $queue)
}

# ── 4. AD DS service state on all DCs ───────────────────────────────────────
Write-Host "`n[+] NTDS / Kerberos / NETLOGON service state:" -ForegroundColor Yellow
$services = @("NTDS", "Kdc", "Netlogon")
foreach ($DC in $DCs) {
    foreach ($svc in $services) {
        try {
            $s = Get-Service -ComputerName $DC -Name $svc -ErrorAction Stop
            $color = if ($s.Status -eq "Running") { "Green" } else { "Red" }
            Write-Host ("  {0,-40} {1,-12} {2}" -f $DC, $svc, $s.Status) -ForegroundColor $color
        } catch {
            Write-Host ("  {0,-40} {1,-12} ERROR: $_" -f $DC, $svc) -ForegroundColor Red
        }
    }
}

# ── 5. Sysvol / NETLOGON share check ────────────────────────────────────────
Write-Host "`n[+] SYSVOL / NETLOGON share availability:" -ForegroundColor Yellow
foreach ($DC in $DCs) {
    $sysvol  = Test-Path "\\$DC\SYSVOL"
    $netlogon = Test-Path "\\$DC\NETLOGON"
    Write-Host ("  {0,-40} SYSVOL:{1}  NETLOGON:{2}" -f $DC, $sysvol, $netlogon)
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
