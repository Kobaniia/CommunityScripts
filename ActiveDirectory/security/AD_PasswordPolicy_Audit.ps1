#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD_PasswordPolicy_Audit.ps1 — Review domain and fine-grained password policies.

.DESCRIPTION
    Reports on the Default Domain Password Policy and all Fine-Grained Password
    Policies (PSOs), flagging configurations that don't meet CIS/NIST benchmarks.

.USAGE
    .\AD_PasswordPolicy_Audit.ps1 [-Domain contoso.com]

.NOTES
    Requires: ActiveDirectory RSAT, Domain Admin or equivalent read rights.
    CIS Benchmark references: CIS Microsoft Windows Server 2022 v1.0.0
#>
param(
    [string]$Domain = (Get-ADDomain).DNSRoot
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "=== AD Password Policy Audit: $Domain ===" -ForegroundColor Cyan

function Test-Policy {
    param($Policy, $Name)
    $issues = @()

    if ($Policy.MinPasswordLength -lt 14)         { $issues += "MinPasswordLength < 14 (is $($Policy.MinPasswordLength))" }
    if ($Policy.MaxPasswordAge.Days -gt 365)       { $issues += "MaxPasswordAge > 365 days" }
    if ($Policy.MinPasswordAge.Days -lt 1)         { $issues += "MinPasswordAge < 1 day" }
    if ($Policy.PasswordHistoryCount -lt 24)       { $issues += "PasswordHistoryCount < 24 (is $($Policy.PasswordHistoryCount))" }
    if (-not $Policy.ComplexityEnabled)            { $issues += "Complexity NOT enabled" }
    if ($Policy.ReversibleEncryptionEnabled)       { $issues += "ReversibleEncryption is ENABLED (critical!)" }
    if ($Policy.LockoutThreshold -eq 0)            { $issues += "Lockout threshold = 0 (no lockout!)" }
    elseif ($Policy.LockoutThreshold -gt 5)        { $issues += "LockoutThreshold > 5 (is $($Policy.LockoutThreshold))" }
    if ($Policy.LockoutDuration.Minutes -lt 15 -and $Policy.LockoutThreshold -ne 0) {
        $issues += "LockoutDuration < 15 min"
    }

    Write-Host "`n  Policy: $Name" -ForegroundColor Yellow
    Write-Host ("  {0,-30} {1}" -f "MinPasswordLength",        $Policy.MinPasswordLength)
    Write-Host ("  {0,-30} {1}" -f "MaxPasswordAge",            $Policy.MaxPasswordAge)
    Write-Host ("  {0,-30} {1}" -f "MinPasswordAge",            $Policy.MinPasswordAge)
    Write-Host ("  {0,-30} {1}" -f "PasswordHistoryCount",      $Policy.PasswordHistoryCount)
    Write-Host ("  {0,-30} {1}" -f "ComplexityEnabled",         $Policy.ComplexityEnabled)
    Write-Host ("  {0,-30} {1}" -f "ReversibleEncryption",      $Policy.ReversibleEncryptionEnabled)
    Write-Host ("  {0,-30} {1}" -f "LockoutThreshold",          $Policy.LockoutThreshold)
    Write-Host ("  {0,-30} {1}" -f "LockoutDuration",           $Policy.LockoutDuration)
    Write-Host ("  {0,-30} {1}" -f "LockoutObservationWindow",  $Policy.LockoutObservationWindow)

    if ($issues.Count -gt 0) {
        Write-Host "`n  [FINDINGS]" -ForegroundColor Red
        foreach ($i in $issues) { Write-Host "    ⚠ $i" -ForegroundColor Red }
    } else {
        Write-Host "`n  [PASS] All checked settings meet minimum benchmarks." -ForegroundColor Green
    }
    return $issues.Count
}

# Default Domain Policy
Write-Host "`n[+] Default Domain Password Policy:" -ForegroundColor Cyan
$ddp    = Get-ADDefaultDomainPasswordPolicy -Identity $Domain
$ddpIssues = Test-Policy -Policy $ddp -Name "Default Domain Policy"

# Fine-Grained Password Policies
Write-Host "`n[+] Fine-Grained Password Policies (PSOs):" -ForegroundColor Cyan
$psos = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
if (-not $psos) {
    Write-Host "  No PSOs defined."
} else {
    foreach ($pso in $psos) {
        $applies = Get-ADFineGrainedPasswordPolicySubject -Identity $pso.Name
        $psoIssues = Test-Policy -Policy $pso -Name $pso.Name
        Write-Host ("  Applies to: {0}" -f ($applies.Name -join ", "))
    }
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
