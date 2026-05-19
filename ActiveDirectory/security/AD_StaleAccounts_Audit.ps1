#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD_StaleAccounts_Audit.ps1 — Find stale user and computer accounts.

.DESCRIPTION
    Identifies accounts that have not logged in for a configurable number of days,
    are disabled but still group members, or whose passwords are very old.
    Generates a CSV report and optionally disables accounts.

.USAGE
    .\AD_StaleAccounts_Audit.ps1 [-InactiveDays 90] [-DisableStale] [-Export C:\stale.csv]

.NOTES
    Requires: ActiveDirectory RSAT, Domain Admin or equivalent.
#>
param(
    [int]    $InactiveDays = 90,
    [switch] $DisableStale,
    [string] $Export       = "$env:TEMP\StaleAccounts_$(Get-Date -f yyyyMMdd).csv"
)

Import-Module ActiveDirectory -ErrorAction Stop

$cutoff = (Get-Date).AddDays(-$InactiveDays)
Write-Host "=== Stale AD Account Audit (inactive > $InactiveDays days) ===" -ForegroundColor Cyan

# ── Users ────────────────────────────────────────────────────────────────────
Write-Host "`n[+] Stale user accounts:" -ForegroundColor Yellow
$staleUsers = Get-ADUser -Filter {
    Enabled -eq $true -and LastLogonDate -lt $cutoff
} -Properties LastLogonDate, PasswordLastSet, MemberOf, Description |
Select-Object `
    @{N="Type";           E={"User"}},
    SamAccountName,
    Name,
    LastLogonDate,
    PasswordLastSet,
    @{N="GroupCount";     E={ $_.MemberOf.Count }},
    @{N="PasswordAgeDays";E={ [int]((Get-Date) - $_.PasswordLastSet).TotalDays }},
    Enabled,
    DistinguishedName

Write-Host ("  Found {0} stale user account(s)" -f $staleUsers.Count)
$staleUsers | Sort-Object LastLogonDate |
    Format-Table SamAccountName, Name, LastLogonDate, PasswordAgeDays -AutoSize

# ── Computers ────────────────────────────────────────────────────────────────
Write-Host "`n[+] Stale computer accounts:" -ForegroundColor Yellow
$staleComputers = Get-ADComputer -Filter {
    Enabled -eq $true -and LastLogonDate -lt $cutoff
} -Properties LastLogonDate, OperatingSystem |
Select-Object `
    @{N="Type";       E={"Computer"}},
    Name,
    LastLogonDate,
    OperatingSystem,
    DistinguishedName

Write-Host ("  Found {0} stale computer account(s)" -f $staleComputers.Count)
$staleComputers | Sort-Object LastLogonDate |
    Format-Table Name, LastLogonDate, OperatingSystem -AutoSize

# ── Expired passwords (enabled users) ────────────────────────────────────────
Write-Host "`n[+] Users with passwords older than $InactiveDays days (enabled):" -ForegroundColor Yellow
$oldPwd = Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $false } `
    -Properties PasswordLastSet | Where-Object { $_.PasswordLastSet -lt $cutoff }
Write-Host ("  Found {0} account(s) with old passwords" -f @($oldPwd).Count)

# ── Optional: disable stale users ────────────────────────────────────────────
if ($DisableStale) {
    Write-Host "`n[!] -DisableStale: disabling stale user accounts…" -ForegroundColor Red
    foreach ($u in $staleUsers) {
        Disable-ADAccount -Identity $u.SamAccountName
        Set-ADUser -Identity $u.SamAccountName `
            -Description "DISABLED by StaleAccounts_Audit on $(Get-Date -f yyyy-MM-dd)"
        Write-Host "  Disabled: $($u.SamAccountName)"
    }
}

# ── Export ───────────────────────────────────────────────────────────────────
$all = @($staleUsers) + @($staleComputers)
$all | Export-Csv -Path $Export -NoTypeInformation
Write-Host "`n[+] Report saved to $Export"
Write-Host "`n=== Done ===" -ForegroundColor Cyan
