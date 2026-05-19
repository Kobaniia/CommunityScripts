#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD_Kerberoastable_Accounts.ps1 — Find service accounts vulnerable to Kerberoasting.

.DESCRIPTION
    Identifies user accounts with Service Principal Names (SPNs) registered,
    which are potential Kerberoasting targets. Highlights high-value targets
    (admin group members, privileged accounts) and reports password age.

.USAGE
    .\AD_Kerberoastable_Accounts.ps1 [-Export C:\kerberoast.csv]

.NOTES
    Requires: ActiveDirectory RSAT.
    Kerberoasting allows offline cracking of service account password hashes
    obtained via TGS tickets — high-value target if account has high privileges.
#>
param(
    [string]$Export = "$env:TEMP\Kerberoastable_$(Get-Date -f yyyyMMdd).csv"
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "=== Kerberoastable Account Finder ===" -ForegroundColor Cyan
Write-Host "[*] Searching for accounts with SPNs …"

$accounts = Get-ADUser -Filter { ServicePrincipalName -like "*" -and Enabled -eq $true } `
    -Properties ServicePrincipalName, PasswordLastSet, MemberOf, LastLogonDate, AdminCount

$findings = @()

foreach ($a in $accounts) {
    $pwdAge = if ($a.PasswordLastSet) {
        [int]((Get-Date) - $a.PasswordLastSet).TotalDays
    } else { 9999 }

    # Check if member of privileged groups
    $privGroups = $a.MemberOf | ForEach-Object {
        $gn = ($_ -split ",")[0] -replace "CN=",""
        $gn
    } | Where-Object { $_ -match "Admin|Operator|Backup|Schema" }

    $risk = if ($a.AdminCount -eq 1 -or $privGroups) { "HIGH" }
            elseif ($pwdAge -gt 365)                   { "MEDIUM" }
            else                                        { "LOW" }

    $findings += [PSCustomObject]@{
        Risk            = $risk
        SamAccountName  = $a.SamAccountName
        Name            = $a.Name
        PasswordAgeDays = $pwdAge
        SPNCount        = $a.ServicePrincipalName.Count
        SPNs            = ($a.ServicePrincipalName -join "; ")
        AdminCount      = $a.AdminCount
        PrivGroups      = ($privGroups -join ", ")
        LastLogon       = $a.LastLogonDate
    }
}

# Display
$findings | Sort-Object @{E={
    switch ($_.Risk) { "HIGH" {0} "MEDIUM" {1} "LOW" {2} default {3} }
}} | Format-Table Risk, SamAccountName, PasswordAgeDays, SPNCount, PrivGroups -AutoSize

# Highlight HIGH
$highRisk = $findings | Where-Object { $_.Risk -eq "HIGH" }
if ($highRisk) {
    Write-Host "`n[!] HIGH-RISK Kerberoastable accounts (privileged + SPN):" -ForegroundColor Red
    foreach ($h in $highRisk) {
        Write-Host ("  {0,-30} AdminCount={1}  PwdAge={2}d  SPNs: {3}" -f `
            $h.SamAccountName, $h.AdminCount, $h.PasswordAgeDays, $h.SPNs) -ForegroundColor Red
    }
}

Write-Host "`n── Summary ──────────────────────────────────────────"
Write-Host "  Total Kerberoastable : $($findings.Count)"
Write-Host "  HIGH risk            : $(($findings | Where-Object Risk -eq 'HIGH').Count)"
Write-Host "  MEDIUM risk          : $(($findings | Where-Object Risk -eq 'MEDIUM').Count)"
Write-Host "  LOW risk             : $(($findings | Where-Object Risk -eq 'LOW').Count)"

$findings | Export-Csv -Path $Export -NoTypeInformation
Write-Host "`n[+] Report saved to $Export"
Write-Host "`n=== Done ===" -ForegroundColor Cyan
