#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD_LockedAccounts_Report.ps1 — Find and report all locked-out AD accounts.

.DESCRIPTION
    Queries Active Directory for all locked accounts, shows last bad password
    attempt, bad password count, and the locking DC if available via event logs.

.USAGE
    .\AD_LockedAccounts_Report.ps1 [-Unlock] [-Export C:\report.csv]

.NOTES
    Requires: ActiveDirectory RSAT module, Domain Admin or equivalent read rights.
#>
param(
    [switch]$Unlock,
    [string]$Export
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "=== Active Directory Locked Account Report ===" -ForegroundColor Cyan
Write-Host "[*] Scanning for locked accounts…"

$locked = Search-ADAccount -LockedOut |
    Where-Object { $_.ObjectClass -eq "user" } |
    Select-Object `
        SamAccountName,
        Name,
        DistinguishedName,
        @{N="BadPwdCount";    E={ (Get-ADUser $_.SamAccountName -Properties BadPwdCount).BadPwdCount }},
        @{N="LastBadPwdTime"; E={ (Get-ADUser $_.SamAccountName -Properties BadPasswordTime).BadPasswordTime }},
        @{N="LockedOut";      E={ $_.LockedOut }},
        @{N="Enabled";        E={ $_.Enabled }}

if ($locked.Count -eq 0) {
    Write-Host "`n  No locked accounts found." -ForegroundColor Green
    return
}

Write-Host ("`n  Found {0} locked account(s):" -f $locked.Count) -ForegroundColor Yellow
$locked | Format-Table SamAccountName, Name, BadPwdCount, LastBadPwdTime -AutoSize

# Try to find locking DC from Security event log 4740
Write-Host "`n[*] Checking Security event log for lockout source (Event 4740)…"
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4740
        StartTime = (Get-Date).AddHours(-24)
    } -ErrorAction SilentlyContinue

    foreach ($e in $events) {
        $xml     = [xml]$e.ToXml()
        $account = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        $src     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CallerComputerName" }).'#text'
        Write-Host ("  {0,-30} locked from: {1}" -f $account, $src)
    }
} catch {
    Write-Warning "  Could not query event log: $_"
}

# Optional: Unlock
if ($Unlock) {
    Write-Host "`n[!] -Unlock specified. Unlocking all accounts…" -ForegroundColor Red
    foreach ($user in $locked) {
        Unlock-ADAccount -Identity $user.SamAccountName
        Write-Host "  Unlocked: $($user.SamAccountName)"
    }
}

# Optional: Export
if ($Export) {
    $locked | Export-Csv -Path $Export -NoTypeInformation
    Write-Host "`n[+] Report saved to $Export"
}

Write-Host "`n=== Done ===" -ForegroundColor Cyan
