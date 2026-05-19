#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD_PrivilegedGroups_Audit.ps1 — Audit members of high-privilege AD groups.

.DESCRIPTION
    Reports all members (including nested) of Domain Admins, Enterprise Admins,
    Schema Admins, Administrators, and any custom groups you specify.
    Flags service accounts, disabled accounts, and accounts without recent logons.

.USAGE
    .\AD_PrivilegedGroups_Audit.ps1 [-AdditionalGroups "VPN-Admins","SQLAdmins"] [-Export C:\priv.csv]

.NOTES
    Requires: ActiveDirectory RSAT, Domain Admin or equivalent read rights.
#>
param(
    [string[]] $AdditionalGroups = @(),
    [string]   $Export = "$env:TEMP\PrivilegedGroups_$(Get-Date -f yyyyMMdd).csv"
)

Import-Module ActiveDirectory -ErrorAction Stop

$PRIVILEGED_GROUPS = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Print Operators",
    "Server Operators",
    "Group Policy Creator Owners"
) + $AdditionalGroups

Write-Host "=== Privileged Group Membership Audit ===" -ForegroundColor Cyan
$allFindings = @()

foreach ($groupName in $PRIVILEGED_GROUPS) {
    try {
        $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
    } catch {
        Write-Warning "  Group not found: $groupName"
        continue
    }

    Write-Host "`n[Group] $groupName" -ForegroundColor Yellow

    # Recursive membership expansion
    $members = Get-ADGroupMember -Identity $groupName -Recursive | Where-Object { $_.objectClass -eq "user" }

    if ($members.Count -eq 0) {
        Write-Host "  (empty)" -ForegroundColor Green
        continue
    }

    foreach ($m in $members) {
        $user = Get-ADUser -Identity $m.SamAccountName `
            -Properties Enabled, LastLogonDate, PasswordLastSet, Description, ServicePrincipalNames

        $flags = @()
        if (-not $user.Enabled)                          { $flags += "DISABLED" }
        if ($user.LastLogonDate -lt (Get-Date).AddDays(-90) -or -not $user.LastLogonDate) {
            $flags += "STALE(>90d)"
        }
        if ($user.ServicePrincipalNames.Count -gt 0)     { $flags += "SERVICE_ACCOUNT" }
        if ($user.PasswordLastSet -lt (Get-Date).AddDays(-365)) { $flags += "OLD_PASSWORD" }

        $flagStr = if ($flags) { "[" + ($flags -join ",") + "]" } else { "" }
        $color   = if ($flags) { "Red" } else { "White" }
        Write-Host ("  {0,-30} {1,-25} {2}" -f $user.SamAccountName, $user.LastLogonDate, $flagStr) -ForegroundColor $color

        $allFindings += [PSCustomObject]@{
            Group           = $groupName
            SamAccountName  = $user.SamAccountName
            DisplayName     = $user.Name
            Enabled         = $user.Enabled
            LastLogon       = $user.LastLogonDate
            PasswordLastSet = $user.PasswordLastSet
            Flags           = $flagStr
        }
    }
}

$allFindings | Export-Csv -Path $Export -NoTypeInformation
Write-Host "`n[+] Full report saved to $Export"
Write-Host "`n=== Summary: $($allFindings.Count) privileged user memberships found ===" -ForegroundColor Cyan
