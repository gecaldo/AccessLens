# Pulls the user/group fields AccessLens needs from an AD environment and saves them as JSON.

param(
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\data\current_ad.json")
)

$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

Write-Host "Reading AD users..."

$adUsers = Get-ADUser -Filter * -Properties Enabled, PasswordNeverExpires, PasswordNotRequired, LastLogonDate, PasswordLastSet

$users = foreach ($user in $adUsers) {
    [ordered]@{
        id = "user:$($user.SamAccountName)"
        name = $user.Name
        sam_account_name = $user.SamAccountName
        sid = $user.SID.Value
        enabled = [bool]$user.Enabled
        password_never_expires = [bool]$user.PasswordNeverExpires
        password_not_required = [bool]$user.PasswordNotRequired
        last_logon_date = if ($null -ne $user.LastLogonDate) {
            $user.LastLogonDate.ToUniversalTime().ToString("o")
        } else {
            $null
        }
        password_last_set = if ($null -ne $user.PasswordLastSet) {
            $user.PasswordLastSet.ToUniversalTime().ToString("o")
        } else {
            $null
        }
    }
}

Write-Host "Reading AD groups and direct memberships..."

$adGroups = Get-ADGroup -Filter *

$groups = foreach ($group in $adGroups) {
    $members = @()

    try {
        # Keep direct membership instead of flattening nested groups.
        $directMembers = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop

        foreach ($member in $directMembers) {
            if ($member.objectClass -eq "user") {
                $members += "user:$($member.SamAccountName)"
            }
            elseif ($member.objectClass -eq "group") {
                $members += "group:$($member.SamAccountName)"
            }
        }
    }
    catch {
        Write-Warning "Could not read '$($group.Name)': $($_.Exception.Message)"
    }

    [ordered]@{
        id = "group:$($group.SamAccountName)"
        name = $group.Name
        sam_account_name = $group.SamAccountName
        members = $members
    }
}

$snapshot = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    users = @($users)
    groups = @($groups)
}

$outputDirectory = Split-Path -Parent $OutputPath

if ($outputDirectory -and -not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$snapshot |
    ConvertTo-Json -Depth 8 |
    Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "Saved snapshot to: $OutputPath"
