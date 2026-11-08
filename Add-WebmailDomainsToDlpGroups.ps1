<#
.SYNOPSIS
    Adds the webmail domains from text files to existing Purview endpoint DLP
    "Sensitive service domain groups".

.DESCRIPTION
    1. Exports the current tenant configuration (SiteGroupsPsws) to a JSON backup.
    2. For each group/file pair, adds every domain that is not already in the group.
    3. Checks the 100-entry-per-group limit before changing anything.
    4. Runs Set-PolicyConfig with -WhatIf, asks for confirmation, then saves.
    5. Re-reads the configuration from the service and reports the result.

    Before step 1, a file selection window opens for each group so you can pick its
    domain file (.txt with one domain per line, or a .csv with a 'Domain' column).
    Use -NoFilePicker to use the paths in -GroupFiles without a window.

    PREREQUISITES
    - Create each group in the Purview portal first, with at least ONE domain added
      (Endpoint settings > Browser and domain restrictions to sensitive data >
       Sensitive service domain groups). The script copies the structure of that
      existing entry, so it doesn't depend on undocumented field names.
    - ExchangeOnlineManagement module, connected with Connect-IPPSSession using an
      account that may change DLP endpoint settings.
    - Test in a non-production tenant first.

.EXAMPLE
    Connect-IPPSSession -UserPrincipalName admin@contoso.com
    .\Add-WebmailDomainsToDlpGroups.ps1 -WhatIfOnly      # preview only
    .\Add-WebmailDomainsToDlpGroups.ps1                  # preview, confirm, save
    .\Add-WebmailDomainsToDlpGroups.ps1 -NoFilePicker    # use default paths, no window

.NOTES
    The file selection window needs Windows (Windows PowerShell 5.1 or PowerShell 7).
#>
[CmdletBinding()]
param(
    # Group name in Purview  =>  text file with one domain per line
    [hashtable]$GroupFiles = [ordered]@{
        'Webmail - Global & Privacy' = '.\webmail_group1_global_privacy.txt'
        'Webmail - Regional'         = '.\webmail_group2_regional.txt'
    },
    [string]$BackupFolder = '.\DlpBackup',
    [int]$MaxEntriesPerGroup = 100,
    [switch]$WhatIfOnly,
    [switch]$NoFilePicker
)

$ErrorActionPreference = 'Stop'

# --- File selection window -----------------------------------------------------------
function Select-DomainFile {
    param([string]$GroupName, [string]$DefaultPath)

    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title  = "Select the domain file for group '$GroupName'"
    $dialog.Filter = 'Domain lists (*.txt;*.csv)|*.txt;*.csv|All files (*.*)|*.*'
    $dialog.Multiselect = $false

    $startFolder = if ($DefaultPath) { Split-Path -Path $DefaultPath -Parent } else { $null }
    if ($startFolder -and (Test-Path $startFolder)) {
        $dialog.InitialDirectory = (Resolve-Path $startFolder).Path
    } else {
        $dialog.InitialDirectory = (Get-Location).Path
    }
    if ($DefaultPath) { $dialog.FileName = Split-Path -Path $DefaultPath -Leaf }

    # Owner window that stays on top, so the dialog doesn't open behind the console
    $owner = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true; ShowInTaskbar = $false }
    try {
        $result = $dialog.ShowDialog($owner)
    } finally {
        $owner.Dispose()
    }
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        throw "No file selected for group '$GroupName'. Cancelled - no changes saved."
    }
    return $dialog.FileName
}

if (-not $NoFilePicker) {
    if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
        throw 'The file selection window needs Windows. Use -NoFilePicker with -GroupFiles instead.'
    }
    $selected = [ordered]@{}
    foreach ($groupName in @($GroupFiles.Keys)) {
        $selected[$groupName] = Select-DomainFile -GroupName $groupName -DefaultPath $GroupFiles[$groupName]
        Write-Host "[$groupName] file: $($selected[$groupName])" -ForegroundColor Cyan
    }
    $GroupFiles = $selected
}

# --- 0. Check the session ---------------------------------------------------------
if (-not (Get-Command Get-PolicyConfig -ErrorAction SilentlyContinue)) {
    throw 'Get-PolicyConfig not found. Run Connect-IPPSSession first.'
}

# --- 1. Read the configuration and back it up --------------------------------------
$policyConfig = Get-PolicyConfig
$groups = @($policyConfig.SiteGroupsPsws)
if (-not $groups -or $groups.Count -eq 0) {
    throw 'No sensitive service domain groups found. Create the groups in the portal first.'
}

New-Item -ItemType Directory -Path $BackupFolder -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupFile = Join-Path $BackupFolder "SiteGroupsPsws-$stamp.json"
$groups | ConvertTo-Json -Depth 10 | Set-Content -Path $backupFile -Encoding UTF8
Write-Host "Backup saved: $backupFile" -ForegroundColor Cyan

# --- Helpers ------------------------------------------------------------------------
function Get-GroupName($g) {
    if ($g -is [System.Collections.IDictionary]) { return $g['Name'] }
    return $g.Name
}
function Get-GroupAddresses($g) {
    $raw = if ($g -is [System.Collections.IDictionary]) { $g['Addresses'] } else { $g.Addresses }
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    return @($raw | ConvertFrom-Json)          # always an array, even with one entry
}
function Set-GroupAddresses($g, $addresses) {
    $json = ConvertTo-Json -InputObject @($addresses) -Compress -Depth 5
    if ($g -is [System.Collections.IDictionary]) { $g['Addresses'] = $json } else { $g.Addresses = $json }
}
function Read-DomainFile($path) {
    if (-not (Test-Path $path)) { throw "File not found: $path" }
    $lines = if ([IO.Path]::GetExtension($path) -ieq '.csv') {
        $rows = @(Import-Csv -Path $path)
        if ($rows.Count -eq 0 -or -not ($rows[0].PSObject.Properties.Name -contains 'Domain')) {
            throw "CSV file '$path' needs a 'Domain' column."
        }
        $rows | ForEach-Object { $_.Domain }
    } else {
        Get-Content -Path $path
    }
    $lines |
        ForEach-Object { $_.Trim().ToLowerInvariant() } |
        Where-Object { $_ -and -not $_.StartsWith('#') } |
        ForEach-Object { $_ -replace '^[a-z]+://', '' -replace '/+$', '' } |   # strip protocol / trailing slash
        Select-Object -Unique
}

# --- 2. Build the changes per group ------------------------------------------------
$summary = @()
foreach ($groupName in $GroupFiles.Keys) {
    $target = $groups | Where-Object { (Get-GroupName $_) -eq $groupName }
    if (-not $target) {
        $available = ($groups | ForEach-Object { Get-GroupName $_ }) -join ', '
        throw "Group '$groupName' not found. Existing groups: $available"
    }

    $addresses = @(Get-GroupAddresses $target)
    if ($addresses.Count -eq 0) {
        throw "Group '$groupName' is empty. Add one domain in the portal first so the entry format can be copied."
    }
    $template = $addresses[0]
    $existing = @($addresses | ForEach-Object { "$($_.Url)".ToLowerInvariant() })

    $domains  = @(Read-DomainFile $GroupFiles[$groupName])
    $toAdd    = @($domains | Where-Object { $existing -notcontains $_ })

    $newTotal = $addresses.Count + $toAdd.Count
    if ($newTotal -gt $MaxEntriesPerGroup) {
        throw "Group '$groupName' would have $newTotal entries (limit $MaxEntriesPerGroup). Split the file."
    }

    foreach ($d in $toAdd) {
        $entry = $template.PSObject.Copy()      # same fields as the portal-created entry
        $entry.Url = $d
        $addresses += $entry
    }
    Set-GroupAddresses $target $addresses

    $summary += [pscustomobject]@{
        Group      = $groupName
        InFile     = $domains.Count
        AlreadyIn  = $domains.Count - $toAdd.Count
        ToAdd      = $toAdd.Count
        NewTotal   = $newTotal
    }
}

$summary | Format-Table -AutoSize

if (($summary | Measure-Object ToAdd -Sum).Sum -eq 0) {
    Write-Host 'Nothing to add. All domains are already present.' -ForegroundColor Green
    return
}

# --- 3. Preview ----------------------------------------------------------------------
Write-Host 'Preview (WhatIf):' -ForegroundColor Yellow
Set-PolicyConfig -SiteGroupsPsws $groups -WhatIf
if ($WhatIfOnly) { Write-Host 'WhatIfOnly set - no changes saved.' -ForegroundColor Yellow; return }

# --- 4. Confirm and save -------------------------------------------------------------
$answer = Read-Host 'Save these changes to the tenant? Type YES to continue'
if ($answer -ne 'YES') { Write-Host 'Cancelled - no changes saved.'; return }

Set-PolicyConfig -SiteGroupsPsws $groups
Write-Host 'Saved.' -ForegroundColor Green

# --- 5. Verify from the service ------------------------------------------------------
Start-Sleep -Seconds 5
$verified = @((Get-PolicyConfig).SiteGroupsPsws)
foreach ($groupName in $GroupFiles.Keys) {
    $g = $verified | Where-Object { (Get-GroupName $_) -eq $groupName }
    $urls = @(Get-GroupAddresses $g | ForEach-Object { "$($_.Url)".ToLowerInvariant() })
    $missing = @(Read-DomainFile $GroupFiles[$groupName] | Where-Object { $urls -notcontains $_ })
    if ($missing.Count -eq 0) {
        Write-Host "[$groupName] OK - $($urls.Count) entries." -ForegroundColor Green
    } else {
        Write-Warning "[$groupName] $($missing.Count) domain(s) missing: $($missing -join ', ')"
    }
}
Write-Host "To roll back, restore from: $backupFile"
