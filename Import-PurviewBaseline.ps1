<#
.SYNOPSIS
    Deploys the Microsoft Purview E5 Baseline (Sensitivity Labels, DLP & IRM) in a customer's M365 tenant.

.DESCRIPTION
    Implements a "Secure by Default" Purview E5 baseline: Sensitivity Labels, Label Policies,
    Auto-Labeling Policies, DLP Policies, OME branding, and IRM Policies.

    Graph API calls (license detection, SPO settings) use a pure Invoke-RestMethod browser-popup
    flow (Authorization Code + PKCE) — the Microsoft.Graph.Authentication module is not required
    and not imported. This avoids the Microsoft.Identity.Client (MSAL) version conflict that occurs
    when ExchangeOnlineManagement and the Graph SDK are both loaded in the same PowerShell process.

    DISCLAIMER:
    -----------
    This script is provided AS IS without warranty of any kind. The author makes no representations
    or warranties of any kind, express or implied, and shall not be liable for any damages, losses,
    or costs arising from its use. Always test in a non-production tenant before deploying to
    production. Review all created policies before switching them from TestWithNotifications /
    Simulation to Enforce mode. Some configurations (Endpoint DLP indicators, IRM triggering events,
    Adaptive Protection bindings) require additional portal-side configuration steps.

    Author  : Daniel Metzger
    Version : 2.1
    Date    : 2026-07-22

.PARAMETER SecurityAlertsEmail
    Email address for DLP incident reports. Optional.

.PARAMETER SkipAutoLabel
    Skip creation of auto-labeling policies.

.PARAMETER SkipIRM
    Skip creation of Insider Risk Management policies.

.EXAMPLE
    .\Import-PurviewBaseline.ps1 -SecurityAlertsEmail secops@contoso.com
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $SecurityAlertsEmail = '',
    [switch] $SkipIRM
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Script-level tracking
$script:Results      = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Errors       = [System.Collections.Generic.List[string]]::new()
$script:LicenseSkips = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:GraphToken   = $null   # populated by Request-GraphToken during auth
$script:SitCatalog   = @{}     # populated by Get-DlpSensitiveInformationType at start of Section 7

function Add-Result {
    param([string]$Category, [string]$Name, [string]$Status, [string]$Guid = '')
    $script:Results.Add([PSCustomObject]@{
        Category = $Category
        Name     = $Name
        Status   = $Status
        Guid     = $Guid
    })
}
#endregion

#region Helpers
function Add-LicenseSkip {
    param([string]$Feature, [string]$RequiredLicense, [string]$Section)
    $script:LicenseSkips.Add([PSCustomObject]@{
        Section         = $Section
        Feature         = $Feature
        RequiredLicense = $RequiredLicense
    })
    Write-Host "  [license] Skipped: $Feature" -ForegroundColor DarkYellow
    Write-Host "            Requires: $RequiredLicense" -ForegroundColor DarkYellow
}

function Get-ObjGuid($o) {
    if ($null -eq $o) { return '' }
    # IPPS implicit remoting (EOM v3.x) sometimes wraps Guid/ImmutableId in a JSON-like object
    # {"value":"<guid>","Guid":"<guid>"} instead of a plain string. Also handles System.Guid.
    foreach ($propName in @('ImmutableId', 'Guid')) {
        if (-not $o.PSObject.Properties[$propName]) { continue }
        $v = $o.$propName
        if ($null -eq $v) { continue }
        if ($v -is [string] -and $v -ne '')                         { return $v }
        if ($v -is [guid])                                          { return $v.ToString() }
        if ($v.PSObject.Properties['value'] -and $v.value)         { return [string]$v.value }
        $s = [string]$v; if ($s -ne '') { return $s }
    }
    # Fallback: label internal names in this script are GUID-format strings accepted by label cmdlets
    if ($o.PSObject.Properties['Name'] -and $o.Name) {
        $n = [string]$o.Name
        if ($n -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-') { return $n }
    }
    return ''
}

filter Skip-PendingDeletion {
    # Exclude labels that are in pending-deletion tombstone state (deleted from portal,
    # still visible via Get-Label but unusable as parents or in policies).
    if ($_.PSObject.Properties['Deleted'] -and [bool]$_.Deleted)                   { return }
    if ($_.PSObject.Properties['Mode']    -and ([string]$_.Mode) -match 'Pending') { return }
    $_
}

function Get-LabelByName($internalName) {
    # Get-Label -Identity treats GUID-format strings as system Guid lookups, not Name lookups.
    # Enumerate and filter by Name to reliably find labels created with GUID-format internal names.
    # Skip-PendingDeletion excludes tombstone labels so recovery logic can find GUI-created ones.
    Get-Label -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $internalName } |
        Skip-PendingDeletion |
        Select-Object -First 1
}

function Set-LabelColor {
    param([object]$Label, [string]$Color, [string]$LabelName)
    if ($null -eq $Label -or [string]::IsNullOrWhiteSpace($Color)) { return }
    $id = Get-LabelIdentity $Label
    if ([string]::IsNullOrWhiteSpace($id)) { return }
    try {
        Set-Label -Identity $id -AdvancedSettings @{ color = $Color } -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "  [!] Could not set color on '$LabelName': $($_.Exception.Message)"
        $script:Errors.Add("[SensitivityLabel] $LabelName color — $($_.Exception.Message)")
    }
}

function Invoke-OrSkip {
    <#
    Wraps a creation scriptblock. On AlreadyExists retrieves the existing object via $GetScript.
    On other errors records the failure and returns $null.

    IPPS error model (three cases this function must handle):
      A. $obj non-null, no error    — clean creation     — [+] Created
      B. $obj non-null, error fired — IPPS returned the existing object with a non-terminating error
                                      (e.g. New-Label/New-DlpCompliancePolicy returning existing on
                                      DisplayNameConflict / AlreadyExists)  — [~] Already exists
      C. $obj null, any / no error  — IPPS either terminated or silently returned null
                                      (e.g. New-DlpCompliancePolicy swallows error to console stream
                                      without adding to $global:Error)       — GetScript path
    #>
    param(
        [string]      $Category,
        [string]      $Name,
        [scriptblock] $CreateScript,
        [scriptblock] $GetScript
    )

    $local:ErrorActionPreference = 'Stop'

    $prevErrCount    = $global:Error.Count
    $createException = $null
    try {
        $obj = & $CreateScript 2>$null
    }
    catch {
        $obj             = $null
        $createException = $_
    }
    $hadError = ($global:Error.Count -gt $prevErrCount) -or ($null -ne $createException)

    # Helper: detect soft-deleted / pending-deletion tombstone objects returned by IPPS
    $isPendingDeletion = {
        param($o)
        if ($null -eq $o) { return $false }
        if ($o.PSObject.Properties['Deleted']  -and [bool]$o.Deleted)                    { return $true }
        if ($o.PSObject.Properties['Mode']     -and ([string]$o.Mode) -match 'Pending')  { return $true }
        return $false
    }

    # Case A: clean creation
    if ($null -ne $obj -and -not $hadError) {
        Write-Host "  [+] Created: $Name" -ForegroundColor Green
        Add-Result -Category $Category -Name $Name -Status 'Created' -Guid (Get-ObjGuid $obj)
        return $obj
    }

    # Case B: IPPS returned existing object alongside a non-terminating error
    if ($null -ne $obj -and $hadError) {
        if (& $isPendingDeletion $obj) {
            Write-Warning "  [!] '$Name' is in pending deletion state — wait 24-72 hours for Microsoft to purge it, then re-run."
            $script:Errors.Add("[$Category] $Name — PendingDeletion: wait 24-72h then re-run")
            Add-Result -Category $Category -Name $Name -Status 'PendingDeletion'
            return $null
        }
        Write-Host "  [~] Already exists: $Name" -ForegroundColor DarkGray
        Add-Result -Category $Category -Name $Name -Status 'AlreadyExisted' -Guid (Get-ObjGuid $obj)
        return $obj
    }

    # Case C: null return
    $msg = if ($createException) { $createException.Exception.Message }
           elseif ($global:Error.Count -gt $prevErrCount) { $global:Error[0].Exception.Message }
           else { '' }

    # Pending-deletion produces a specific exception on creation attempts
    if ($msg -match 'pending.?delet') {
        Write-Warning "  [!] '$Name' is in pending deletion state — wait 24-72 hours for Microsoft to purge it, then re-run."
        $script:Errors.Add("[$Category] $Name — PendingDeletion: wait 24-72h then re-run")
        Add-Result -Category $Category -Name $Name -Status 'PendingDeletion'
        return $null
    }

    $isAlreadyExists = ($msg -match 'already exist') -or ($msg -match 'duplicate') -or
                       ($msg -match 'already been created') -or ($msg -match 'DisplayNameConflict') -or
                       ($msg -match 'AlreadyExists') -or ($msg -match 'ComplianceRule') -or
                       ($msg -eq '')

    if ($isAlreadyExists) {
        Write-Host "  [~] Already exists: $Name" -ForegroundColor DarkGray
        try {
            $obj = $null
            if ($msg -match "already used by label '([0-9a-fA-F-]{36})'") {
                $obj = Get-Label -Identity $Matches[1] -ErrorAction SilentlyContinue
            }
            if (-not $obj) { $obj = & $GetScript }
            # If GetScript returned a pending-deletion tombstone, treat as non-existent
            if (& $isPendingDeletion $obj) {
                Write-Warning "  [!] '$Name' is in pending deletion state — wait 24-72 hours for Microsoft to purge it, then re-run."
                $script:Errors.Add("[$Category] $Name — PendingDeletion: wait 24-72h then re-run")
                Add-Result -Category $Category -Name $Name -Status 'PendingDeletion'
                return $null
            }
            Add-Result -Category $Category -Name $Name -Status 'AlreadyExisted' -Guid (Get-ObjGuid $obj)
            return $obj
        }
        catch {
            Add-Result -Category $Category -Name $Name -Status 'AlreadyExisted-GetFailed'
            return $null
        }
    }
    else {
        Write-Warning "  [!] Failed to create '$Name': $msg"
        $script:Errors.Add("[$Category] $Name — $msg")
        Add-Result -Category $Category -Name $Name -Status 'Failed'
        return $null
    }
}

function Set-DlpRule {
    <#
    Idempotent DLP rule helper: updates the rule with Set-DlpComplianceRule if it already
    exists, creates it with New-DlpComplianceRule otherwise. Matches the Get→Set/New pattern
    from the working Endpoint DLP example.
    #>
    param([string]$PolicyName, [string]$RuleName, [hashtable]$Params)

    # -Identity alone can return $null even when the rule exists; enumerate as fallback.
    $existing = Get-DlpComplianceRule -Policy $PolicyName -Identity $RuleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        $existing = Get-DlpComplianceRule -Policy $PolicyName -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $RuleName } | Select-Object -First 1
    }

    $updateParams = @{}
    foreach ($k in $Params.Keys) {
        if ($k -notin @('Name', 'Policy')) { $updateParams[$k] = $Params[$k] }
    }

    if ($existing) {
        Set-DlpComplianceRule -Identity $RuleName @updateParams -ErrorAction Stop | Out-Null
        Write-Host "  [~] Updated rule: $RuleName" -ForegroundColor DarkGray
        Add-Result -Category 'DLPRule' -Name $RuleName -Status 'Updated'
    }
    else {
        try {
            New-DlpComplianceRule @Params -ErrorAction Stop | Out-Null
            Write-Host "  [+] Created rule: $RuleName" -ForegroundColor Green
            Add-Result -Category 'DLPRule' -Name $RuleName -Status 'Created'
        }
        catch {
            if ($_.Exception.Message -match 'AlreadyExists|already exists') {
                Set-DlpComplianceRule -Identity $RuleName @updateParams -ErrorAction Stop | Out-Null
                Write-Host "  [~] Updated rule: $RuleName" -ForegroundColor DarkGray
                Add-Result -Category 'DLPRule' -Name $RuleName -Status 'Updated'
            }
            else { throw }
        }
    }
}

function Resolve-Sit {
    <#
    Looks up a sensitive information type (SIT) name against the tenant SIT catalog.
    Falls back to a word-based fuzzy match so that abbreviated names (e.g. "Equivalent ID")
    still resolve when the tenant uses the full form ("Equivalent Identification Number").
    Returns a ContentContainsSensitiveInformation hashtable entry, or $null if not found.
    #>
    param([string]$Name, [string]$MinCount = '1', [string]$ConfidenceLevel = 'High')
    if ($script:SitCatalog.Count -gt 0) {
        $lowerName = $Name.ToLower()
        # 1. Exact case-insensitive match
        $resolved  = $script:SitCatalog[$lowerName]
        if (-not $resolved) {
            # 2. Word-based fuzzy: find catalog entry containing every significant word of our name
            $words    = $lowerName -split '\W+' | Where-Object { $_.Length -gt 2 }
            $resolved = $script:SitCatalog.Values | Where-Object {
                $t = $_.ToLower()
                @($words | Where-Object { -not $t.Contains($_) }).Count -eq 0
            } | Select-Object -First 1
        }
        if (-not $resolved) {
            Write-Warning "  [SIT] Not found in tenant catalog: '$Name' — skipped from rule"
            $script:Errors.Add("[DLP] SIT not in tenant: $Name")
            return $null
        }
        $Name = $resolved
    }
    @{ Name = $Name; minCount = $MinCount; confidenceLevel = $ConfidenceLevel }
}

function Request-GraphToken {
    <#
    Authenticates to Microsoft Graph via an interactive browser popup using OAuth 2.0
    Authorization Code + PKCE (RFC 7636). Opens the default browser, starts a local
    HTTP listener on port 8400 to capture the redirect, then exchanges the code for a
    bearer token. No Microsoft.Graph.Authentication module, no MSAL dependency.
    #>
    param([string[]]$Scopes)

    $clientId    = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # well-known Azure PowerShell public client
    $redirectUri = 'http://localhost:8400/'
    $scopeStr    = ($Scopes + 'offline_access') -join ' '
    $state       = [System.Guid]::NewGuid().ToString('N')
    $base        = 'https://login.microsoftonline.com/organizations/oauth2/v2.0'

    # PKCE: 32 random bytes → base64url (no padding)
    $rng          = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $verifierBytes = [byte[]]::new(32)
    $rng.GetBytes($verifierBytes)
    $codeVerifier  = [System.Convert]::ToBase64String($verifierBytes) -replace '\+','-' -replace '/','_' -replace '=',''

    $sha256        = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes     = $sha256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
    $codeChallenge = [System.Convert]::ToBase64String($hashBytes) -replace '\+','-' -replace '/','_' -replace '=',''

    $authUrl = "$base/authorize" +
               "?client_id=$clientId" +
               "&response_type=code" +
               "&redirect_uri=$([uri]::EscapeDataString($redirectUri))" +
               "&scope=$([uri]::EscapeDataString($scopeStr))" +
               "&state=$state" +
               "&code_challenge=$codeChallenge" +
               "&code_challenge_method=S256" +
               "&prompt=select_account"

    # Start listener before opening browser so the redirect is never missed
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($redirectUri)
    try { $listener.Start() }
    catch { throw "Could not start HTTP listener on port 8400 (may be in use): $($_.Exception.Message)" }

    Write-Host "  Opening browser for Microsoft Graph sign-in..." -ForegroundColor Yellow
    Start-Process $authUrl

    # Wait up to 3 minutes for the user to complete sign-in
    $async = $listener.BeginGetContext($null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne(180000)) {
        $listener.Stop()
        throw 'Graph authentication timed out (3 minutes).'
    }

    $ctx = $listener.EndGetContext($async)

    # Send success page BEFORE stopping the listener — stopping disposes the request queue
    # handle, which causes "Cannot access a disposed object" if Write runs after Stop.
    $html = '<html><body style="font-family:sans-serif;text-align:center;padding-top:80px">' +
            '<h2>Sign-in complete.</h2><p>You may close this browser tab and return to PowerShell.</p></body></html>'
    $buf = [System.Text.Encoding]::UTF8.GetBytes($html)
    $ctx.Response.ContentType     = 'text/html'
    $ctx.Response.ContentLength64 = $buf.Length
    $ctx.Response.OutputStream.Write($buf, 0, $buf.Length)
    $ctx.Response.Close()

    $listener.Stop()

    # Parse query string manually — no System.Web dependency needed
    $query  = $ctx.Request.Url.Query.TrimStart('?')
    $qp     = @{}
    foreach ($pair in $query -split '&') {
        $kv = $pair -split '=', 2
        if ($kv.Count -eq 2) { $qp[$kv[0]] = [uri]::UnescapeDataString($kv[1]) }
    }

    if ($qp['error']) { throw "Auth error: $($qp['error']) — $($qp['error_description'])" }
    if ($qp['state'] -ne $state) { throw 'State mismatch — authentication aborted.' }
    if (-not $qp['code']) { throw 'No authorization code in redirect response.' }

    # Exchange code for token
    $tok = Invoke-RestMethod -Method POST -Uri "$base/token" `
             -ContentType 'application/x-www-form-urlencoded' `
             -Body ("client_id=$clientId" +
                    "&grant_type=authorization_code" +
                    "&code=$([uri]::EscapeDataString($qp['code']))" +
                    "&redirect_uri=$([uri]::EscapeDataString($redirectUri))" +
                    "&code_verifier=$codeVerifier") `
             -ErrorAction Stop

    $script:GraphToken = $tok.access_token
    Write-Host "  Microsoft Graph: authenticated." -ForegroundColor Green
}

function Invoke-GraphApi {
    <#
    Calls the Microsoft Graph REST API using the bearer token from Request-GraphToken.
    Returns a hashtable so callers can use bracket notation ['key'] safely under Set-StrictMode.
    #>
    param(
        [string] $Method,
        [string] $Uri,
        [string] $Body        = '',
        [string] $ContentType = 'application/json'
    )
    if (-not $script:GraphToken) { throw 'Not connected to Graph. Call Request-GraphToken first.' }

    $params = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = @{ Authorization = "Bearer $script:GraphToken" }
        ErrorAction = 'Stop'
    }
    if ($Body)        { $params['Body']        = $Body }
    if ($ContentType) { $params['ContentType'] = $ContentType }

    $result = Invoke-RestMethod @params
    if ($null -ne $result) {
        # Convert PSCustomObject to hashtable for consistent bracket-notation access
        return $result | ConvertTo-Json -Depth 20 | ConvertFrom-Json -AsHashtable
    }
    return $null
}
#endregion

#region 1 — Prerequisites
Write-Host "`n=== Section 1: Prerequisites ===" -ForegroundColor Cyan

# ExchangeOnlineManagement 3.4+ is the only required module.
# Graph API calls use Invoke-RestMethod with a bearer token — no Graph SDK, no MSAL.
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge '2.8.5.201' })) {
    Write-Host "  Installing NuGet provider..." -ForegroundColor Yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
}

$requiredModules = @(
    @{ Name = 'ExchangeOnlineManagement'; MinVersion = '3.4.0' }
)

foreach ($mod in $requiredModules) {
    $installed = Get-Module -ListAvailable -Name $mod.Name |
        Where-Object { $_.Version -ge [version]$mod.MinVersion } |
        Sort-Object Version -Descending |
        Select-Object -First 1
    if (-not $installed) {
        Write-Host "  Installing $($mod.Name) >= $($mod.MinVersion)..." -ForegroundColor Yellow
        Install-Module -Name $mod.Name -MinimumVersion $mod.MinVersion -Force -AllowClobber -Scope CurrentUser
        Write-Host "  Installed $($mod.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "  Module OK: $($mod.Name) v$($installed.Version)" -ForegroundColor DarkGray
    }
    Import-Module $mod.Name -MinimumVersion $mod.MinVersion -Force -ErrorAction Stop
}
#endregion

#region 2 — Authentication
Write-Host "`n=== Section 2: Authentication ===" -ForegroundColor Cyan

Write-Host "  Connecting to Exchange Online..." -ForegroundColor Yellow
Connect-ExchangeOnline -ShowBanner:$false

Write-Host "  Connecting to IPPSSession (Security & Compliance)..." -ForegroundColor Yellow
Connect-IPPSSession -ShowBanner:$false

# Derive primary domain (requires EO connection above)
$primaryDomain = (Get-AcceptedDomain | Where-Object { $_.Default }).DomainName
Write-Host "  Primary domain: $primaryDomain" -ForegroundColor Green

# Graph via browser popup (Authorization Code + PKCE) — no MSAL, no Graph SDK module.
Write-Host "  Connecting to Microsoft Graph (browser sign-in — no MSAL)..." -ForegroundColor Yellow
Request-GraphToken -Scopes @('SharePointTenantSettings.ReadWrite.All', 'Organization.Read.All')
#endregion

#region 3 — Platform Prerequisites
Write-Host "`n=== Section 3: Platform Prerequisites ===" -ForegroundColor Cyan

# ---- License detection ----
Write-Host "  Detecting tenant licenses..." -ForegroundColor Yellow
$script:TenantPlans = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
try {
    $skuResponse = Invoke-GraphApi -Method GET -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus'
    foreach ($sku in $skuResponse['value']) {
        if ($sku['capabilityStatus'] -eq 'Enabled') {
            foreach ($plan in $sku['servicePlans']) {
                if ($plan['provisioningStatus'] -eq 'Success') {
                    $null = $script:TenantPlans.Add([string]$plan['servicePlanName'])
                }
            }
        }
    }
    Write-Host "  License detection complete ($($script:TenantPlans.Count) active service plans)." -ForegroundColor Green
}
catch {
    Write-Warning "  Could not read license info — all features will be attempted: $($_.Exception.Message)"
}

$detected = $script:TenantPlans.Count -gt 0

$script:HasRMS = (-not $detected) -or (
    $script:TenantPlans.Contains('RIGHTSMANAGEMENT') -or
    $script:TenantPlans.Contains('RMS_S_ENTERPRISE')  -or
    $script:TenantPlans.Contains('RMS_S_PREMIUM')     -or
    $script:TenantPlans.Contains('RMS_S_PREMIUM2')    -or
    $script:TenantPlans.Contains('MIP_S_CLP1')        -or
    $script:TenantPlans.Contains('MIP_S_CLP2')
)

$script:HasExchangeP2 = (-not $detected) -or (
    $script:TenantPlans.Contains('EXCHANGE_S_ENTERPRISE')
)

$script:HasIRM = (-not $detected) -or (
    $script:TenantPlans.Contains('INSIDER_RISK_MANAGEMENT') -or
    $script:TenantPlans.Contains('COMMUNICATIONS_COMPLIANCE')
)

Write-Host ("  RMS/AIP encryption : {0}" -f $(if ($script:HasRMS)        { 'Available' } else { 'NOT licensed' })) -ForegroundColor $(if ($script:HasRMS)        { 'Green' } else { 'Yellow' })
Write-Host ("  Exchange Online P2 : {0}" -f $(if ($script:HasExchangeP2) { 'Available' } else { 'NOT licensed' })) -ForegroundColor $(if ($script:HasExchangeP2) { 'Green' } else { 'Yellow' })
Write-Host ("  Insider Risk Mgmt  : {0}" -f $(if ($script:HasIRM)        { 'Available' } else { 'NOT licensed' })) -ForegroundColor $(if ($script:HasIRM)        { 'Green' } else { 'Yellow' })

# Enable sensitivity labels for Office files in SharePoint / OneDrive
Write-Host "  Enabling sensitivity label processing for Office files (SPO/OneDrive)..." -ForegroundColor Yellow
try {
    $spoSettings = Invoke-GraphApi -Method GET -Uri 'https://graph.microsoft.com/beta/admin/sharepoint/settings'
    if ($spoSettings['isAzureADLabelsSyncEnabled'] -eq $true) {
        Write-Host "  Already enabled — Office Online can process encrypted files." -ForegroundColor DarkGray
    }
    else {
        Invoke-GraphApi -Method PATCH -Uri 'https://graph.microsoft.com/beta/admin/sharepoint/settings' `
            -Body '{"isAzureADLabelsSyncEnabled": true}' | Out-Null
        Write-Host "  Enabled — Office Online will process encrypted files in SPO/OneDrive." -ForegroundColor Green
    }
}
catch {
    Write-Warning "  Could not enable SPO sensitivity label processing: $($_.Exception.Message)"
    $script:Errors.Add("[Platform] SPO sensitivity label processing — $($_.Exception.Message)")
}

if (-not $script:HasRMS) {
    Add-LicenseSkip -Feature 'Azure RMS / label encryption' `
                    -RequiredLicense 'Azure Information Protection Plan 1/2, or Microsoft 365 E3/E5' `
                    -Section 'Platform'
}

Write-Host "  Syncing sensitivity labels to Azure AD (container labels)..." -ForegroundColor Yellow
try {
    Execute-AzureAdLabelSync -ErrorAction Stop
    Write-Host "  Azure AD label sync triggered." -ForegroundColor Green
}
catch {
    Write-Warning "  Could not trigger Azure AD label sync: $($_.Exception.Message)"
    $script:Errors.Add("[Platform] Azure AD label sync — $($_.Exception.Message)")
}

if ($script:HasExchangeP2) {
    Write-Host "  Enabling Exchange IRM internal licensing..." -ForegroundColor Yellow
    try {
        Set-IRMConfiguration -InternalLicensingEnabled $true -ErrorAction Stop
        Write-Host "  Exchange IRM enabled." -ForegroundColor Green
    }
    catch {
        Write-Warning "  Could not enable Exchange IRM: $($_.Exception.Message)"
        $script:Errors.Add("[Platform] Exchange IRM — $($_.Exception.Message)")
    }
}
else {
    Add-LicenseSkip -Feature 'Exchange IRM (InternalLicensingEnabled)' `
                    -RequiredLicense 'Exchange Online Plan 2, or Microsoft 365 E3/E5' `
                    -Section 'Platform'
}

#endregion

#region 4 — Sensitivity Labels
Write-Host "`n=== Section 4: Sensitivity Labels ===" -ForegroundColor Cyan

$colorPersonal = '#70AD47'
$colorPublic   = '#FFC000'
$colorGeneral  = '#4472C4'
$colorConf     = '#ED7D31'
$colorHC       = '#800020'

# Load all live (non-pending-deletion) labels once.
# -WarningAction SilentlyContinue suppresses IPPS warnings about orphaned sub-labels
# (labels whose parent is itself in pending-deletion state).
Write-Host "  Loading existing labels..." -ForegroundColor Yellow
$script:LiveLabels = @(Get-Label -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Skip-PendingDeletion)
Write-Host "  $($script:LiveLabels.Count) live label(s) found in tenant." -ForegroundColor DarkGray

function Get-LabelIdentity {
    # Returns the most useful identity string for a label object.
    # Tries Guid first (safe for Set-Label -Identity), then ImmutableId, then Name.
    param([object]$Label)
    if ($null -eq $Label) { return '' }
    foreach ($prop in @('Guid', 'ImmutableId', 'Name')) {
        if (-not $Label.PSObject.Properties[$prop]) { continue }
        $v = $Label.$prop
        if ($v -is [string] -and $v -ne '') { return $v }
        if ($v -is [guid])                  { return $v.ToString() }
        $s = [string]$v; if ($s -ne '')     { return $s }
    }
    return ''
}

function Ensure-Label {
    <#
    Check-first label creation. Searches $script:LiveLabels by DisplayName and parent
    relationship so no extra Get-Label calls are made. If found, returns the existing
    label. If not found, creates with New-Label (no forced internal Name, avoiding
    conflicts with pending-deletion tombstones that share the same display name).
    #>
    param(
        [string]    $DisplayName,
        [object]    $Parent  = $null,  # parent label object; $null = top-level
        [hashtable] $Params            # passed directly to New-Label if creation needed
    )

    if ($Parent) {
        # Collect all known identifiers of the parent so we can match against ParentId
        # regardless of which identifier format IPPS stored.
        $parentIds = @(foreach ($p in @('Guid', 'ImmutableId', 'Name')) {
            if ($Parent.PSObject.Properties[$p]) {
                $v = $Parent.$p
                $s = if ($v -is [string]) { $v } elseif ($v -is [guid]) { $v.ToString() } else { [string]$v }
                if ($s -ne '') { $s }
            }
        })
        $existing = $script:LiveLabels |
            Where-Object { $_.DisplayName -eq $DisplayName -and ($parentIds -contains $_.ParentId) } |
            Select-Object -First 1
    } else {
        $existing = $script:LiveLabels |
            Where-Object { $_.DisplayName -eq $DisplayName -and -not $_.ParentId } |
            Select-Object -First 1
    }

    if ($existing) {
        Write-Host "  [~] Already exists: $DisplayName" -ForegroundColor DarkGray
        Add-Result -Category 'SensitivityLabel' -Name $DisplayName -Status 'AlreadyExisted' -Guid (Get-LabelIdentity $existing)
        return $existing
    }

    try {
        $createParams = if ($Params.ContainsKey('Name')) { $Params } else {
            $p = $Params.Clone(); $p['Name'] = [System.Guid]::NewGuid().ToString(); $p
        }
        $new = New-Label @createParams -ErrorAction Stop
        $script:LiveLabels += $new
        Write-Host "  [+] Created: $DisplayName" -ForegroundColor Green
        Add-Result -Category 'SensitivityLabel' -Name $DisplayName -Status 'Created' -Guid (Get-LabelIdentity $new)
        return $new
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match 'pending.?delet') {
            Write-Warning "  [!] '$DisplayName' is blocked by a pending-deletion tombstone — wait 24-72 hours for Microsoft to purge it, then re-run."
        } else {
            Write-Warning "  [!] Failed to create '$DisplayName': $msg"
        }
        $script:Errors.Add("[SensitivityLabel] $DisplayName — $msg")
        Add-Result -Category 'SensitivityLabel' -Name $DisplayName -Status 'Failed'
        return $null
    }
}

function Set-LabelEncryption {
    param(
        [object]    $Label,
        [string]    $LabelName,
        [hashtable] $EncryptionParams
    )
    if ($null -eq $Label) { return }
    if (-not $script:HasRMS) {
        Add-LicenseSkip -Feature "Label encryption: $LabelName" `
                        -RequiredLicense 'Azure Information Protection Plan 1/2, or Microsoft 365 E3/E5' `
                        -Section 'SensitivityLabel'
        return
    }
    $id = Get-LabelIdentity $Label
    try {
        Set-Label -Identity $id @EncryptionParams -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        Write-Host "  [+] Encryption set: $LabelName" -ForegroundColor Green
    }
    catch {
        Write-Warning "  [!] Could not set encryption on '$LabelName': $($_.Exception.Message)"
        $script:Errors.Add("[SensitivityLabel] $LabelName encryption — $($_.Exception.Message)")
    }
}

# ---- Personal ----
$lblPersonal = Ensure-Label -DisplayName 'Personal' -Params @{
    DisplayName = 'Personal'
    ContentType = 'File,Email'
    Tooltip     = 'Content not related to company business. No corporate controls applied.'
}
Set-LabelColor -Label $lblPersonal -Color $colorPersonal -LabelName 'Personal'

# ---- Public ----
$lblPublic = Ensure-Label -DisplayName 'Public' -Params @{
    DisplayName = 'Public'
    ContentType = 'File,Email'
    Tooltip     = 'Business data prepared and approved for public consumption.'
}
Set-LabelColor -Label $lblPublic -Color $colorPublic -LabelName 'Public'

# ---- General ----
$lblGeneral = Ensure-Label -DisplayName 'General' -Params @{
    DisplayName                                   = 'General'
    ContentType                                   = 'File,Email,Site,UnifiedGroup'
    Tooltip                                       = 'Business data not intended for public; can be shared with trusted external partners.'
    SiteAndGroupProtectionEnabled                 = $true
    SiteAndGroupProtectionPrivacy                 = 'Private'
    SiteAndGroupProtectionAllowAccessToGuestUsers = $true
    SiteExternalSharingControlType                = 'ExistingExternalUserSharingOnly'
}
Set-LabelColor -Label $lblGeneral -Color $colorGeneral -LabelName 'General'

# ---- Confidential (parent) ----
$lblConfidential = Ensure-Label -DisplayName 'Confidential' -Params @{
    DisplayName  = 'Confidential'
    Tooltip      = 'Confidential business data. Apply a sub-label to classify content.'
    IsLabelGroup = $true
}
Set-LabelColor -Label $lblConfidential -Color $colorConf -LabelName 'Confidential'

# ---- Highly Confidential (parent) ----
$lblHC = Ensure-Label -DisplayName 'Highly Confidential' -Params @{
    DisplayName  = 'Highly Confidential'
    Tooltip      = 'Highly confidential data. Apply a sub-label to classify content.'
    IsLabelGroup = $true
}
Set-LabelColor -Label $lblHC -Color $colorHC -LabelName 'Highly Confidential'

# ---- Confidential sub-labels ----
if ($null -ne $lblConfidential) {
    $confId = Get-LabelIdentity $lblConfidential

    $lblConfNDA = Ensure-Label -DisplayName 'Anyone NDA (No Encryption)' -Parent $lblConfidential -Params @{
        DisplayName                                   = 'Anyone NDA (No Encryption)'
        ParentId                                      = $confId
        ContentType                                   = 'File,Email,Site,UnifiedGroup'
        Tooltip                                       = 'Confidential data shared under NDA with external parties. No encryption applied.'
        ApplyContentMarkingFooterEnabled              = $true
        ApplyContentMarkingFooterText                 = 'Classified as Confidential'
        ApplyContentMarkingFooterFontSize             = 10
        ApplyContentMarkingFooterFontColor            = '#000000'
        ApplyContentMarkingFooterAlignment            = 'Center'
        SiteAndGroupProtectionEnabled                 = $true
        SiteAndGroupProtectionPrivacy                 = 'Private'
        SiteAndGroupProtectionAllowAccessToGuestUsers = $true
        SiteExternalSharingControlType                = 'ExternalUserAndGuestSharing'
    }
    Set-LabelColor -Label $lblConfNDA -Color $colorConf -LabelName 'Confidential\Anyone NDA (No Encryption)'

    $lblConfAllEmployees = Ensure-Label -DisplayName 'All Employees' -Parent $lblConfidential -Params @{
        DisplayName                                   = 'All Employees'
        ParentId                                      = $confId
        ContentType                                   = 'File,Email,Site,UnifiedGroup'
        Tooltip                                       = 'Confidential data — all employees have full permissions. Owners can track and revoke.'
        ApplyContentMarkingFooterEnabled              = $true
        ApplyContentMarkingFooterText                 = 'Classified as Confidential'
        ApplyContentMarkingFooterFontSize             = 10
        ApplyContentMarkingFooterFontColor            = '#000000'
        ApplyContentMarkingFooterAlignment            = 'Center'
        SiteAndGroupProtectionEnabled                 = $true
        SiteAndGroupProtectionPrivacy                 = 'Private'
        SiteAndGroupProtectionAllowAccessToGuestUsers = $false
        SiteExternalSharingControlType                = 'ExternalUserSharingOnly'
    }
    Set-LabelEncryption -Label $lblConfAllEmployees -LabelName 'Confidential\All Employees' -EncryptionParams @{
        EncryptionEnabled                           = $true
        EncryptionProtectionType                    = 'Template'
        EncryptionRightsDefinitions                 = "$primaryDomain`:VIEW,DOCEDIT,EDIT,EXTRACT,VIEWRIGHTSDATA,OBJMODEL,EXPORT,PRINT,REPLY,REPLYALL,FORWARD"
        EncryptionOfflineAccessDays                 = 30
        EncryptionContentExpiredOnDateInDaysOrNever = 'Never'
    }
    Set-LabelColor -Label $lblConfAllEmployees -Color $colorConf -LabelName 'Confidential\All Employees'

    $lblConfSpecific = Ensure-Label -DisplayName 'Specific People' -Parent $lblConfidential -Params @{
        DisplayName                                   = 'Specific People'
        ParentId                                      = $confId
        ContentType                                   = 'File,Email,Site,UnifiedGroup'
        Tooltip                                       = 'Confidential data you can share with trusted people inside and outside the org.'
        ApplyContentMarkingFooterEnabled              = $true
        ApplyContentMarkingFooterText                 = 'Classified as Confidential'
        ApplyContentMarkingFooterFontSize             = 10
        ApplyContentMarkingFooterFontColor            = '#000000'
        ApplyContentMarkingFooterAlignment            = 'Center'
        SiteAndGroupProtectionEnabled                 = $true
        SiteAndGroupProtectionPrivacy                 = 'Private'
        SiteAndGroupProtectionAllowAccessToGuestUsers = $true
        SiteExternalSharingControlType                = 'ExternalUserAndGuestSharing'
    }
    Set-LabelEncryption -Label $lblConfSpecific -LabelName 'Confidential\Specific People' -EncryptionParams @{
        EncryptionEnabled        = $true
        EncryptionProtectionType = 'UserDefined'
        EncryptionPromptUser     = $true
        EncryptionEncryptOnly    = $true
    }
    Set-LabelColor -Label $lblConfSpecific -Color $colorConf -LabelName 'Confidential\Specific People'
}
else {
    Write-Warning "  Skipping Confidential sub-labels — parent label not available."
    $lblConfNDA = $null; $lblConfAllEmployees = $null; $lblConfSpecific = $null
}

# ---- Highly Confidential sub-labels ----
if ($null -ne $lblHC) {
    $hcId = Get-LabelIdentity $lblHC

    $lblHCAllEmployees = Ensure-Label -DisplayName 'All Employees' -Parent $lblHC -Params @{
        DisplayName                                   = 'All Employees'
        ParentId                                      = $hcId
        ContentType                                   = 'File,Email,Site,UnifiedGroup'
        Tooltip                                       = 'Highly confidential data — all employees can view/edit/reply. Owners can track and revoke.'
        ApplyContentMarkingFooterEnabled              = $true
        ApplyContentMarkingFooterText                 = 'Highly Confidential'
        ApplyContentMarkingFooterFontSize             = 10
        ApplyContentMarkingFooterFontColor            = '#000000'
        ApplyContentMarkingFooterAlignment            = 'Center'
        ApplyWaterMarkingEnabled                      = $true
        ApplyWaterMarkingText                         = 'Highly Confidential'
        ApplyWaterMarkingLayout                       = 'Diagonal'
        ApplyWaterMarkingFontColor                    = '#FF0000'
        SiteAndGroupProtectionEnabled                 = $true
        SiteAndGroupProtectionPrivacy                 = 'Private'
        SiteAndGroupProtectionAllowAccessToGuestUsers = $false
        SiteExternalSharingControlType                = 'Disabled'
        SiteAndGroupProtectionAllowLimitedAccess      = $true
    }
    Set-LabelEncryption -Label $lblHCAllEmployees -LabelName 'Highly Confidential\All Employees' -EncryptionParams @{
        EncryptionEnabled                           = $true
        EncryptionProtectionType                    = 'Template'
        EncryptionRightsDefinitions                 = "$primaryDomain`:VIEW,DOCEDIT,EDIT,EXTRACT,VIEWRIGHTSDATA,OBJMODEL,EXPORT,PRINT,REPLY,REPLYALL,FORWARD"
        EncryptionOfflineAccessDays                 = 7
        EncryptionContentExpiredOnDateInDaysOrNever = 'Never'
    }
    Set-LabelColor -Label $lblHCAllEmployees -Color $colorHC -LabelName 'Highly Confidential\All Employees'

    $lblHCSpecific = Ensure-Label -DisplayName 'Specific People' -Parent $lblHC -Params @{
        DisplayName                                   = 'Specific People'
        ParentId                                      = $hcId
        ContentType                                   = 'File,Email,Site,UnifiedGroup'
        Tooltip                                       = 'Highly confidential — can only be viewed by named recipients.'
        ApplyContentMarkingFooterEnabled              = $true
        ApplyContentMarkingFooterText                 = 'Highly Confidential'
        ApplyContentMarkingFooterFontSize             = 10
        ApplyContentMarkingFooterFontColor            = '#000000'
        ApplyContentMarkingFooterAlignment            = 'Center'
        ApplyWaterMarkingEnabled                      = $true
        ApplyWaterMarkingText                         = 'Highly Confidential'
        ApplyWaterMarkingLayout                       = 'Diagonal'
        ApplyWaterMarkingFontColor                    = '#FF0000'
        SiteAndGroupProtectionEnabled                 = $true
        SiteAndGroupProtectionPrivacy                 = 'Private'
        SiteAndGroupProtectionAllowAccessToGuestUsers = $false
        SiteExternalSharingControlType                = 'Disabled'
        SiteAndGroupProtectionBlockAccess             = $true
    }
    Set-LabelEncryption -Label $lblHCSpecific -LabelName 'Highly Confidential\Specific People' -EncryptionParams @{
        EncryptionEnabled        = $true
        EncryptionProtectionType = 'UserDefined'
        EncryptionPromptUser     = $true
        EncryptionDoNotForward   = $true
    }
    Set-LabelColor -Label $lblHCSpecific -Color $colorHC -LabelName 'Highly Confidential\Specific People'
}
else {
    Write-Warning "  Skipping Highly Confidential sub-labels — parent label not available."
    $lblHCAllEmployees = $null; $lblHCSpecific = $null
}
#endregion

#region 5 — Label Policies
Write-Host "`n=== Section 5: Label Policies ===" -ForegroundColor Cyan

$allLabelNames = @(
    (Get-LabelIdentity $lblPersonal), (Get-LabelIdentity $lblPublic), (Get-LabelIdentity $lblGeneral),
    (Get-LabelIdentity $lblConfNDA), (Get-LabelIdentity $lblConfAllEmployees), (Get-LabelIdentity $lblConfSpecific),
    (Get-LabelIdentity $lblHCAllEmployees), (Get-LabelIdentity $lblHCSpecific)
) | Where-Object { $_ }

$docDefaultLabelId   = Get-LabelIdentity $lblConfAllEmployees   # documents: Confidential\All Employees
$emailDefaultLabelId = Get-LabelIdentity $lblGeneral             # email / meetings: General

$policySettings = @{
    mandatory                     = 'true'
    requiredowngradejustification = 'true'
    attachmentaction              = 'Automatic'
    disablemandatoryinoutlook     = 'false'
    siteandgroupmandatory         = 'true'
    policytipnotificationhelplink = 'https://aka.ms/securesharing'
}
if ($docDefaultLabelId)   { $policySettings['defaultlabelid']                = $docDefaultLabelId }
if ($emailDefaultLabelId) { $policySettings['outlookdefaultlabel']            = $emailDefaultLabelId }
if ($emailDefaultLabelId) { $policySettings['outlookdefaultlabelformeetings'] = $emailDefaultLabelId }

$null = Invoke-OrSkip -Category 'LabelPolicy' -Name 'Purview Baseline — All Users' `
    -CreateScript {
        New-LabelPolicy -Name 'Purview Baseline — All Users' `
            -Labels $allLabelNames `
            -ExchangeLocation All -ModernGroupLocation All -SharePointLocation All `
            -Settings $policySettings
    } `
    -GetScript { Get-LabelPolicy -Identity 'Purview Baseline — All Users' }

# Always apply settings so re-runs keep default labels current
try {
    Set-LabelPolicy -Identity 'Purview Baseline — All Users' -Settings $policySettings -ErrorAction Stop
    Write-Host "  [~] Policy settings applied: Purview Baseline — All Users" -ForegroundColor DarkGray
}
catch {
    $msg = $_.Exception.Message
    if ($msg -notmatch 'deleted|IsDeletedException|pending') {
        Write-Warning "  [!] Could not update policy settings: $msg"
        $script:Errors.Add("[LabelPolicy] Settings update — $msg")
    }
}
#endregion

#region 6 — Endpoint DLP Global Settings
Write-Host "`n=== Section 6: Endpoint DLP Global Settings ===" -ForegroundColor Cyan

# NOTE: Browser and domain restrictions, restricted app groups, VPN config, and evidence
# collection storage must be configured in the Purview portal (Endpoint DLP Settings).
$null = Invoke-OrSkip -Category 'PolicyConfig' -Name 'Endpoint DLP Global Config' `
    -CreateScript {
        Set-PolicyConfig -EndpointDlpGlobalSettings @(
            @{ Setting = 'PathExclusion';    Value = 'C:\\Windows\\' },
            @{ Setting = 'MacPathExclusion'; Value = '/System/' },
            @{ Setting = 'CloudAppMode';     Value = 'Block' }
        )
    } `
    -GetScript { Get-PolicyConfig }
#endregion


#region 7 — DLP Policies
Write-Host "`n=== Section 7: DLP Policies (TestWithNotifications mode) ===" -ForegroundColor Cyan

# Build case-insensitive SIT name map so Resolve-Sit can handle renamed/versioned SITs
try {
    Get-DlpSensitiveInformationType -ErrorAction Stop | ForEach-Object {
        $script:SitCatalog[$_.Name.ToLower()] = $_.Name
    }
    Write-Host "  Loaded $($script:SitCatalog.Count) SITs from tenant catalog." -ForegroundColor DarkGray
}
catch {
    Write-Warning "  [!] Could not load SIT catalog ($($_.Exception.Message)) — SIT names used as-is."
}

$script:HasAdaptiveProtParam = (Get-Command New-DlpComplianceRule -ErrorAction SilentlyContinue) -and
                                (Get-Command New-DlpComplianceRule).Parameters.ContainsKey('InsiderRiskLevelForAdaptiveProtection')

# ---- DLP-01 — Block External Sharing Internal+ ----
Write-Host "  Creating DLP-01..." -ForegroundColor Yellow
$dlp01 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-01 Block External Sharing Internal+' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-01 Block External Sharing Internal+' `
            -Mode TestWithNotifications `
            -ExchangeLocation All -SharePointLocation All -OneDriveLocation All -TeamsLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-01 Block External Sharing Internal+' }

if ($null -ne $dlp01) {
    $dlp01Sits = @(
        Resolve-Sit 'EU Social Security Number or Equivalent ID'
        Resolve-Sit 'Credit Card Number'
        Resolve-Sit 'U.S. Social Security Number (SSN)'
        Resolve-Sit 'International Banking Account Number (IBAN)'
        Resolve-Sit 'Azure Storage Account Key'

        Resolve-Sit 'GitHub Personal Access Token'
    ) | Where-Object { $_ }
    if ($dlp01Sits.Count -gt 0) {
        Set-DlpRule -PolicyName 'Purview DLP-01 Block External Sharing Internal+' -RuleName 'DLP-01 Rule' -Params @{
            Name                                = 'DLP-01 Rule'
            Policy                              = 'Purview DLP-01 Block External Sharing Internal+'
            ContentContainsSensitiveInformation = $dlp01Sits
            AccessScope                         = 'NotInOrganization'
            BlockAccess                         = $true
            BlockAccessScope                    = 'All'
            NotifyUser                          = @('SiteAdmin', 'LastModifier', 'Owner')
            NotifyPolicyTipCustomText           = 'This file contains sensitive information and cannot be shared externally.'
            GenerateAlert                       = $true
            AlertProperties                     = @{ AggregationType = 'SimpleAggregation'; Threshold = 3; TimeWindow = 60 }
        }
    } else {
        Write-Warning "  [!] Skipping DLP-01 rule — no valid SITs resolved from tenant catalog."
    }
}

# ---- DLP-02 — Block Anonymous Links Confidential+ ----
Write-Host "  Creating DLP-02..." -ForegroundColor Yellow
$dlp02 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-02 Block Anonymous Links Confidential+' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-02 Block Anonymous Links Confidential+' `
            -Mode TestWithNotifications -SharePointLocation All -OneDriveLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-02 Block Anonymous Links Confidential+' }

if ($null -ne $dlp02) {
    $dlp02Sits = @(
        Resolve-Sit 'EU Social Security Number or Equivalent ID'
        Resolve-Sit 'Credit Card Number'
        Resolve-Sit 'U.S. Social Security Number (SSN)'
        Resolve-Sit 'International Banking Account Number (IBAN)'
    ) | Where-Object { $_ }
    if ($dlp02Sits.Count -gt 0) {
        Set-DlpRule -PolicyName 'Purview DLP-02 Block Anonymous Links Confidential+' -RuleName 'DLP-02 Rule' -Params @{
            Name                                = 'DLP-02 Rule'
            Policy                              = 'Purview DLP-02 Block Anonymous Links Confidential+'
            ContentContainsSensitiveInformation = $dlp02Sits
            BlockAccess                         = $true
            BlockAccessScope                    = 'PerAnonymousUser'
            NotifyUser                          = @('SiteAdmin', 'LastModifier', 'Owner')
            NotifyPolicyTipCustomText           = "This file contains sensitive information. Sharing via 'Anyone with the link' is blocked."
        }
    } else { Write-Warning "  [!] Skipping DLP-02 rule — no valid SITs resolved from tenant catalog." }
}

# ---- DLP-03 — Block Unauthorized Guest Domains ----
Write-Host "  Creating DLP-03..." -ForegroundColor Yellow
$dlp03 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-03 Block Unauthorized Guest Domains' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-03 Block Unauthorized Guest Domains' `
            -Mode TestWithNotifications `
            -ExchangeLocation All -SharePointLocation All -OneDriveLocation All -TeamsLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-03 Block Unauthorized Guest Domains' }

if ($null -ne $dlp03) {
    $dlp03Sits = @(
        Resolve-Sit 'EU Social Security Number or Equivalent ID' '5'
        Resolve-Sit 'Credit Card Number' '5'
        Resolve-Sit 'U.S. Social Security Number (SSN)' '5'
        Resolve-Sit 'International Banking Account Number (IBAN)' '5'
    ) | Where-Object { $_ }
    if ($dlp03Sits.Count -gt 0) {
        # ExceptIfRecipientDomainIs left empty — populate with approved partner domains after deployment
        Set-DlpRule -PolicyName 'Purview DLP-03 Block Unauthorized Guest Domains' -RuleName 'DLP-03 Rule' -Params @{
            Name                                = 'DLP-03 Rule'
            Policy                              = 'Purview DLP-03 Block Unauthorized Guest Domains'
            ContentContainsSensitiveInformation = $dlp03Sits
            AccessScope                         = 'NotInOrganization'
            BlockAccess                         = $true
            BlockAccessScope                    = 'All'
            NotifyUser                          = @('SiteAdmin', 'LastModifier', 'Owner')
            NotifyPolicyTipCustomText           = 'This file contains sensitive information. Provide justification to share with external guests.'
            NotifyAllowOverride                 = 'WithJustification'
        }
    } else { Write-Warning "  [!] Skipping DLP-03 rule — no valid SITs resolved from tenant catalog." }
}

# ---- DLP-04 — PII Financial Data Exfiltration ----
Write-Host "  Creating DLP-04..." -ForegroundColor Yellow
$dlp04 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-04 PII Financial Data Exfiltration' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-04 PII Financial Data Exfiltration' `
            -Mode TestWithNotifications `
            -ExchangeLocation All -SharePointLocation All -OneDriveLocation All `
            -TeamsLocation All -EndpointDlpLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-04 PII Financial Data Exfiltration' }

if ($null -ne $dlp04) {
    $dlp04Sits = @(
        Resolve-Sit 'EU Social Security Number or Equivalent ID' '5'
        Resolve-Sit 'EU Passport Number' '5'
        Resolve-Sit 'Credit Card Number' '5'
        Resolve-Sit 'U.S. Social Security Number (SSN)' '5'
        Resolve-Sit 'U.S. Individual Taxpayer Identification Number (ITIN)' '5'
        Resolve-Sit 'International Banking Account Number (IBAN)' '5'
    ) | Where-Object { $_ }
    if ($dlp04Sits.Count -gt 0) {
        $dlp04Params = @{
            Name                                = 'DLP-04 Rule'
            Policy                              = 'Purview DLP-04 PII Financial Data Exfiltration'
            ContentContainsSensitiveInformation = $dlp04Sits
            BlockAccess                         = $true
            BlockAccessScope                    = 'All'
            NotifyAllowOverride                 = 'WithJustification'
            NotifyUser                          = @('SiteAdmin', 'LastModifier')
            GenerateAlert                       = $true
            AlertProperties                     = @{ AggregationType = 'SimpleAggregation'; Threshold = 3; TimeWindow = 60 }
        }
        if (-not [string]::IsNullOrWhiteSpace($SecurityAlertsEmail)) {
            $dlp04Params['GenerateIncidentReport'] = $SecurityAlertsEmail
            $dlp04Params['IncidentReportContent']  = 'All'
        }
        Set-DlpRule -PolicyName 'Purview DLP-04 PII Financial Data Exfiltration' -RuleName 'DLP-04 Rule' -Params $dlp04Params
    } else { Write-Warning "  [!] Skipping DLP-04 rule — no valid SITs resolved from tenant catalog." }
}

# ---- DLP-05 — Credentials in Files Hard Block ----
Write-Host "  Creating DLP-05..." -ForegroundColor Yellow
$dlp05 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-05 Credentials in Files Hard Block' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-05 Credentials in Files Hard Block' `
            -Mode TestWithNotifications `
            -SharePointLocation All -OneDriveLocation All -EndpointDlpLocation All -TeamsLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-05 Credentials in Files Hard Block' }

if ($null -ne $dlp05) {
    $dlp05Sits = @(
        Resolve-Sit 'Azure Storage Account Key'

        Resolve-Sit 'GitHub Personal Access Token'
        Resolve-Sit 'Google API Key'
        Resolve-Sit 'Azure SAS'
    ) | Where-Object { $_ }
    if ($dlp05Sits.Count -gt 0) {
        $dlp05Params = @{
            Name                                = 'DLP-05 Rule'
            Policy                              = 'Purview DLP-05 Credentials in Files Hard Block'
            ContentContainsSensitiveInformation = $dlp05Sits
            BlockAccess                         = $true
            BlockAccessScope                    = 'All'
            GenerateAlert                       = $true
            AlertProperties                     = @{ AggregationType = 'SimpleAggregation'; Threshold = 3; TimeWindow = 60 }
        }
        if (-not [string]::IsNullOrWhiteSpace($SecurityAlertsEmail)) {
            $dlp05Params['GenerateIncidentReport'] = $SecurityAlertsEmail
            $dlp05Params['IncidentReportContent']  = 'All'
        }
        Set-DlpRule -PolicyName 'Purview DLP-05 Credentials in Files Hard Block' -RuleName 'DLP-05 Rule' -Params $dlp05Params
    } else { Write-Warning "  [!] Skipping DLP-05 rule — no valid SITs resolved from tenant catalog." }
}

# ---- DLP-06 — Endpoint Block HC to USB/Bluetooth ----
Write-Host "  Creating DLP-06..." -ForegroundColor Yellow
$dlp06 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-06 Endpoint Block HC to USB Bluetooth' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-06 Endpoint Block HC to USB Bluetooth' `
            -Mode TestWithNotifications -EndpointDlpLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-06 Endpoint Block HC to USB Bluetooth' }

if ($null -ne $dlp06) {
    $dlp06Sits = @(
        Resolve-Sit 'Azure Storage Account Key'

        Resolve-Sit 'GitHub Personal Access Token'
        Resolve-Sit 'Google API Key'
        Resolve-Sit 'Azure SAS'
        Resolve-Sit 'EU Social Security Number or Equivalent ID' '5'
        Resolve-Sit 'Credit Card Number' '5'
    ) | Where-Object { $_ }
    if ($dlp06Sits.Count -gt 0) {
        $dlp06Params = @{
            Name                                = 'DLP-06 Rule'
            Policy                              = 'Purview DLP-06 Endpoint Block HC to USB Bluetooth'
            ContentContainsSensitiveInformation = $dlp06Sits
            EndpointDlpRestrictions = @(
                @{ Setting = 'RemovableMedia'; Value = 'Block' },
                @{ Setting = 'NetworkShare';   Value = 'Block' },
                @{ Setting = 'Print';          Value = 'Block' },
                @{ Setting = 'CopyPaste';                      Value = 'Block' },
                @{ Setting = 'UnallowedBluetoothTransferApps'; Value = 'Block' }
            )
            NotifyEndpointUser  = @{
                NotificationTitle   = 'default:Action blocked'
                NotificationContent = 'default:Copying Highly Confidential files to removable media, network shares, or Bluetooth is blocked by policy.'
            }
            ReportSeverityLevel = 'High'
        }
        if ($script:HasAdaptiveProtParam) { $dlp06Params['InsiderRiskLevelForAdaptiveProtection'] = 'Elevated' }
        Set-DlpRule -PolicyName 'Purview DLP-06 Endpoint Block HC to USB Bluetooth' -RuleName 'DLP-06 Rule' -Params $dlp06Params
    } else { Write-Warning "  [!] Skipping DLP-06 rule — no valid SITs resolved from tenant catalog." }
}

# ---- DLP-07 — Endpoint Block Upload to Unapproved Cloud ----
Write-Host "  Creating DLP-07..." -ForegroundColor Yellow
$dlp07 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-07 Endpoint Block Upload Unapproved Cloud' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-07 Endpoint Block Upload Unapproved Cloud' `
            -Mode TestWithNotifications -EndpointDlpLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-07 Endpoint Block Upload Unapproved Cloud' }

if ($null -ne $dlp07) {
    $dlp07Sits = @(
        Resolve-Sit 'EU Social Security Number or Equivalent ID' '5'
        Resolve-Sit 'EU Passport Number' '5'
        Resolve-Sit 'Credit Card Number' '5'
        Resolve-Sit 'U.S. Social Security Number (SSN)' '5'
        Resolve-Sit 'International Banking Account Number (IBAN)' '5'
        Resolve-Sit 'Azure Storage Account Key'

    ) | Where-Object { $_ }
    if ($dlp07Sits.Count -gt 0) {
        $dlp07Params = @{
            Name                                = 'DLP-07 Rule'
            Policy                              = 'Purview DLP-07 Endpoint Block Upload Unapproved Cloud'
            ContentContainsSensitiveInformation = $dlp07Sits
            EndpointDlpRestrictions = @(
                @{ Setting = 'CloudEgress'; Value = 'Block' }
            )
            NotifyEndpointUser  = @{
                NotificationTitle   = 'default:Action blocked'
                NotificationContent = 'default:Uploading sensitive content to non-approved cloud services is blocked. Use OneDrive for Business.'
            }
            ReportSeverityLevel = 'High'
        }
        if ($script:HasAdaptiveProtParam) { $dlp07Params['InsiderRiskLevelForAdaptiveProtection'] = 'Elevated' }
        Set-DlpRule -PolicyName 'Purview DLP-07 Endpoint Block Upload Unapproved Cloud' -RuleName 'DLP-07 Rule' -Params $dlp07Params
    } else { Write-Warning "  [!] Skipping DLP-07 rule — no valid SITs resolved from tenant catalog." }
}

# ---- DLP-08 — Endpoint Block Access by Unallowed Apps ----
Write-Host "  Creating DLP-08..." -ForegroundColor Yellow
# NOTE: Define the "Cloud Sync apps" restricted app group in Purview portal > Endpoint DLP Settings
# > Restricted app groups before this rule takes effect.
$dlp08 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-08 Endpoint Block Unallowed Apps' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-08 Endpoint Block Unallowed Apps' `
            -Mode TestWithNotifications -EndpointDlpLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-08 Endpoint Block Unallowed Apps' }

if ($null -ne $dlp08) {
    $dlp08Sits = @(
        Resolve-Sit 'Azure Storage Account Key'

        Resolve-Sit 'GitHub Personal Access Token'
        Resolve-Sit 'Google API Key'
        Resolve-Sit 'Azure SAS'
    ) | Where-Object { $_ }
    if ($dlp08Sits.Count -gt 0) {
        $dlp08Params = @{
            Name                                = 'DLP-08 Rule'
            Policy                              = 'Purview DLP-08 Endpoint Block Unallowed Apps'
            ContentContainsSensitiveInformation = $dlp08Sits
            EndpointDlpRestrictions = @(
                @{ Setting = 'UnallowedApps'; Value = 'Block' }
            )
            NotifyEndpointUser  = @{
                NotificationTitle   = 'default:Action blocked'
                NotificationContent = 'default:Access to Highly Confidential files by this application is blocked by policy.'
            }
            ReportSeverityLevel = 'High'
        }
        if ($script:HasAdaptiveProtParam) { $dlp08Params['InsiderRiskLevelForAdaptiveProtection'] = 'Elevated' }
        Set-DlpRule -PolicyName 'Purview DLP-08 Endpoint Block Unallowed Apps' -RuleName 'DLP-08 Rule' -Params $dlp08Params
    } else { Write-Warning "  [!] Skipping DLP-08 rule — no valid SITs resolved from tenant catalog." }
}

# ---- DLP-09 — Teams Block Sensitive Messages ----
Write-Host "  Creating DLP-09..." -ForegroundColor Yellow
$dlp09 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-09 Teams Block Sensitive Messages' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-09 Teams Block Sensitive Messages' `
            -Mode TestWithNotifications -TeamsLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-09 Teams Block Sensitive Messages' }

if ($null -ne $dlp09) {
    $dlp09Sits = @(
        Resolve-Sit 'Credit Card Number'
        Resolve-Sit 'U.S. Social Security Number (SSN)'
        Resolve-Sit 'EU Social Security Number or Equivalent ID'
        Resolve-Sit 'International Banking Account Number (IBAN)'
        Resolve-Sit 'Azure Storage Account Key'

        Resolve-Sit 'GitHub Personal Access Token'
    ) | Where-Object { $_ }
    if ($dlp09Sits.Count -gt 0) {
        Set-DlpRule -PolicyName 'Purview DLP-09 Teams Block Sensitive Messages' -RuleName 'DLP-09 Rule' -Params @{
            Name                                = 'DLP-09 Rule'
            Policy                              = 'Purview DLP-09 Teams Block Sensitive Messages'
            ContentContainsSensitiveInformation = $dlp09Sits
            BlockAccess               = $true
            BlockAccessScope          = 'All'
            NotifyUser                = @('Owner')
            NotifyPolicyTipCustomText = 'This message contains sensitive information classified as Confidential or higher.'
        }
    } else { Write-Warning "  [!] Skipping DLP-09 rule — no valid SITs resolved from tenant catalog." }
}

# ---- DLP-10 — Copilot Content Protection ----
Write-Host "  Creating DLP-10..." -ForegroundColor Yellow
# NOTE: Once the tenant enables the dedicated Copilot DLP location, update this policy
# via Set-DlpCompliancePolicy. TeamsLocation All is used as a compatible fallback.
$dlp10 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Purview DLP-10 Copilot Content Protection' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Purview DLP-10 Copilot Content Protection' `
            -Mode TestWithNotifications -TeamsLocation All
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Purview DLP-10 Copilot Content Protection' }

if ($null -ne $dlp10) {
    $dlp10Sits = @(
        Resolve-Sit 'Azure Storage Account Key'

        Resolve-Sit 'GitHub Personal Access Token'
        Resolve-Sit 'Credit Card Number'
        Resolve-Sit 'U.S. Social Security Number (SSN)'
    ) | Where-Object { $_ }
    if ($dlp10Sits.Count -gt 0) {
        Set-DlpRule -PolicyName 'Purview DLP-10 Copilot Content Protection' -RuleName 'DLP-10 Rule' -Params @{
            Name                                = 'DLP-10 Rule'
            Policy                              = 'Purview DLP-10 Copilot Content Protection'
            ContentContainsSensitiveInformation = $dlp10Sits
            BlockAccess      = $true
            BlockAccessScope = 'All'
            GenerateAlert    = $true
            AlertProperties  = @{ AggregationType = 'SimpleAggregation'; Threshold = 3; TimeWindow = 60 }
        }
    } else { Write-Warning "  [!] Skipping DLP-10 rule — no valid SITs resolved from tenant catalog." }
}

# ---- DLP-11 — Endpoint Block Unlabeled Files to USB ----
Write-Host "  Creating DLP-11..." -ForegroundColor Yellow
$dlp11 = Invoke-OrSkip -Category 'DLPPolicy' -Name 'Endpoint DLP - Unlabeled to USB' `
    -CreateScript {
        New-DlpCompliancePolicy -Name 'Endpoint DLP - Unlabeled to USB' `
            -EndpointDlpLocation All `
            -Mode Enable `
            -Comment 'Blocks unlabeled files from being copied to USB.'
    } `
    -GetScript { Get-DlpCompliancePolicy -Identity 'Endpoint DLP - Unlabeled to USB' }

if ($null -ne $dlp11) {
    Set-DlpRule -PolicyName 'Endpoint DLP - Unlabeled to USB' -RuleName 'Block Unlabeled -> USB' -Params @{
        Name                    = 'Block Unlabeled -> USB'
        Policy                  = 'Endpoint DLP - Unlabeled to USB'
        ContentIsNotLabeled     = $true
        EndpointDlpRestrictions = @( @{ Setting = 'RemovableMedia'; Value = 'Block' } )
        NotifyEndpointUser      = @{
            NotificationTitle   = 'default:Action blocked'
            NotificationContent = 'default:Copying unlabeled files to USB is blocked by policy.'
        }
        ReportSeverityLevel     = 'High'
    }
}
#endregion

#region 8 — OME Branding
Write-Host "`n=== Section 8: OME Branding ===" -ForegroundColor Cyan

if ($script:HasExchangeP2) {
    # NOTE: Customize -EmailText, -IntroductionText, and -PortalText with your organization's
    # specific branding, legal disclaimer, and support contact before going to production.
    $null = Invoke-OrSkip -Category 'OME' -Name 'OME Configuration' `
        -CreateScript {
            Set-OMEConfiguration -Identity 'OME Configuration' -OTPEnabled $true -SocialIdSignIn $true
            Get-OMEConfiguration -Identity 'OME Configuration'
        } `
        -GetScript { Get-OMEConfiguration -Identity 'OME Configuration' }
}
else {
    Write-Host "  Skipping OME — license not available." -ForegroundColor DarkYellow
    Add-LicenseSkip -Feature 'OME branding configuration' `
                    -RequiredLicense 'Exchange Online Plan 2, or Microsoft 365 E3/E5' `
                    -Section 'OME'
}
#endregion

#region 9 — IRM Policies
if (-not $SkipIRM) {
    Write-Host "`n=== Section 9: Insider Risk Management Policies ===" -ForegroundColor Cyan

    if (-not $script:HasIRM) {
        Write-Host "  Skipping IRM — license not available." -ForegroundColor DarkYellow
        Add-LicenseSkip -Feature 'Insider Risk Management policies (IRM-01/02/03)' `
                        -RequiredLicense 'Microsoft 365 E5, or Microsoft 365 E5 Compliance add-on' `
                        -Section 'IRMPolicy'
    }
    elseif (Get-Command New-InsiderRiskPolicy -ErrorAction SilentlyContinue) {

        Write-Host "  Configuring IRM global settings (analytics, privacy)..." -ForegroundColor Yellow
        $irmSettingsCmd = Get-Command Set-InsiderRiskSettings -ErrorAction SilentlyContinue
        if ($irmSettingsCmd) {
            $irmSetParams = $irmSettingsCmd.Parameters
            $settingsArgs = @{}
            if ($irmSetParams.ContainsKey('EnableAnalytics'))      { $settingsArgs['EnableAnalytics']      = $true }
            if ($irmSetParams.ContainsKey('AnalyticsEnabled'))     { $settingsArgs['AnalyticsEnabled']     = $true }
            if ($irmSetParams.ContainsKey('EnableAnonymization'))  { $settingsArgs['EnableAnonymization']  = $true }
            if ($irmSetParams.ContainsKey('AnonymizationEnabled')) { $settingsArgs['AnonymizationEnabled'] = $true }
            if ($settingsArgs.Count -gt 0) {
                try {
                    Set-InsiderRiskSettings @settingsArgs -ErrorAction Stop
                    Write-Host "  IRM global settings configured." -ForegroundColor Green
                }
                catch {
                    Write-Warning "  Could not configure IRM settings: $($_.Exception.Message)"
                    $script:Errors.Add("[IRMPolicy] IRM global settings — $($_.Exception.Message)")
                }
            }
            else {
                Write-Host "  IRM settings: no recognised parameters — configure analytics in the Purview portal." -ForegroundColor DarkGray
            }
        }
        else {
            Write-Host "  Set-InsiderRiskSettings not available — configure analytics in the Purview portal." -ForegroundColor DarkGray
        }

        $irmCmdParams = (Get-Command New-InsiderRiskPolicy).Parameters
        $hasTemplate  = $irmCmdParams.ContainsKey('InsiderRiskPolicyTemplate')
        $hasScenario  = $irmCmdParams.ContainsKey('InsiderRiskScenario')
        $hasBehav     = $irmCmdParams.ContainsKey('BehaviouralAnalyticsEnabled')

        # IRM-01 — Data Leaks (All Users)
        # NOTE: Triggering events and behavioral indicators must be enabled in the portal.
        $null = Invoke-OrSkip -Category 'IRMPolicy' -Name 'IRM-01 Data Leaks' `
            -CreateScript {
                $p = @{ Name = 'IRM-01 Data Leaks' }
                if ($hasTemplate) { $p['InsiderRiskPolicyTemplate'] = 'DataLeaksByUsers' }
                if ($hasScenario) { $p['InsiderRiskScenario']       = 'LeakOfInformation' }
                if ($hasBehav)    { $p['BehaviouralAnalyticsEnabled'] = $true }
                New-InsiderRiskPolicy @p
            } `
            -GetScript { Get-InsiderRiskPolicy -Identity 'IRM-01 Data Leaks' }

        # IRM-02 — Data Theft by Departing Users
        # NOTE: Uses Azure AD account disable as the triggering event.
        # For richer signals, configure an HR Connector in the Purview portal.
        $null = Invoke-OrSkip -Category 'IRMPolicy' -Name 'IRM-02 Data Theft Departing Users' `
            -CreateScript {
                $p = @{ Name = 'IRM-02 Data Theft Departing Users' }
                if ($hasTemplate) { $p['InsiderRiskPolicyTemplate'] = 'DataTheftByDepartingUsers' }
                if ($hasScenario) { $p['InsiderRiskScenario']       = 'DepartingEmployeeSPV' }
                if ($hasBehav)    { $p['BehaviouralAnalyticsEnabled'] = $true }
                New-InsiderRiskPolicy @p
            } `
            -GetScript { Get-InsiderRiskPolicy -Identity 'IRM-02 Data Theft Departing Users' }

        # IRM-03 — Data Leaks by Priority Users
        # NOTE: Create Priority User Groups in the portal and assign them to this policy.
        $null = Invoke-OrSkip -Category 'IRMPolicy' -Name 'IRM-03 Data Leaks Priority Users' `
            -CreateScript {
                $p = @{ Name = 'IRM-03 Data Leaks Priority Users' }
                if ($hasTemplate) { $p['InsiderRiskPolicyTemplate'] = 'DataLeaksByPriorityUsers' }
                if ($hasScenario) { $p['InsiderRiskScenario']       = 'HighValueEmployeeSPV' }
                if ($hasBehav)    { $p['BehaviouralAnalyticsEnabled'] = $true }
                New-InsiderRiskPolicy @p
            } `
            -GetScript { Get-InsiderRiskPolicy -Identity 'IRM-03 Data Leaks Priority Users' }
    }
    else {
        Write-Host '  IRM cmdlets not available in this module version — skipping.' -ForegroundColor Yellow
        Add-LicenseSkip -Feature 'Insider Risk Management policies (cmdlet unavailable in this module version)' `
                        -RequiredLicense 'Microsoft 365 E5 + ExchangeOnlineManagement module with IRM cmdlets' `
                        -Section 'IRMPolicy'
    }
}
else {
    Write-Host "`n=== Section 9: IRM Policies — SKIPPED (-SkipIRM) ===" -ForegroundColor Yellow
}
#endregion

#region 10 — Adaptive Protection Binding
Write-Host "`n=== Section 10: Adaptive Protection — DLP Binding ===" -ForegroundColor Cyan

if (-not $script:HasIRM) {
    Write-Host "  Skipping Adaptive Protection — license not available." -ForegroundColor DarkYellow
    Add-LicenseSkip -Feature 'Adaptive Protection (DLP-IRM risk binding)' `
                    -RequiredLicense 'Microsoft 365 E5, or Microsoft 365 E5 Compliance add-on' `
                    -Section 'AdaptiveProtection'
}
elseif (Get-Command Enable-InsiderRiskAdaptiveProtection -ErrorAction SilentlyContinue) {
    $null = Invoke-OrSkip -Category 'AdaptiveProtection' -Name 'Enable Adaptive Protection' `
        -CreateScript { Enable-InsiderRiskAdaptiveProtection -Confirm:$false } `
        -GetScript { Get-InsiderRiskAdaptiveProtectionSettings }
}
else {
    Write-Host '  Enable-InsiderRiskAdaptiveProtection is not available in the installed EOM version.' -ForegroundColor Yellow
    Write-Host '  Enable Adaptive Protection manually: Purview portal > Insider Risk Management > Adaptive Protection.' -ForegroundColor Yellow
}
#endregion

#region 11 — Summary Report
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  PURVIEW E5 BASELINE — DEPLOYMENT SUMMARY" -ForegroundColor Cyan
Write-Host "  Tenant: $primaryDomain" -ForegroundColor Cyan
Write-Host "  Deployed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$categories = $script:Results | Select-Object -ExpandProperty Category -Unique
foreach ($cat in $categories) {
    $catResults = $script:Results | Where-Object { $_.Category -eq $cat }
    $created  = @($catResults | Where-Object { $_.Status -eq 'Created' }).Count
    $existed  = @($catResults | Where-Object { $_.Status -like 'AlreadyExisted*' }).Count
    $failed   = @($catResults | Where-Object { $_.Status -eq 'Failed' }).Count

    Write-Host "`n  [$cat]" -ForegroundColor Cyan
    Write-Host "    Created:         $created" -ForegroundColor Green
    Write-Host "    Already existed: $existed" -ForegroundColor DarkGray
    if ($failed -gt 0) { Write-Host "    Failed:          $failed" -ForegroundColor Red }
}

Write-Host "`n  Key Label GUIDs (for policy settings reference):" -ForegroundColor Cyan
$guidMap = @{
    'General'                      = (Get-LabelIdentity $lblGeneral)          -replace '^$','N/A'
    'Confidential'                 = (Get-LabelIdentity $lblConfidential)     -replace '^$','N/A'
    'Confidential\All Employees'   = (Get-LabelIdentity $lblConfAllEmployees) -replace '^$','N/A'
    'Confidential\Specific People' = (Get-LabelIdentity $lblConfSpecific)     -replace '^$','N/A'
    'Highly Confidential'          = (Get-LabelIdentity $lblHC)               -replace '^$','N/A'
    'HC\All Employees'             = (Get-LabelIdentity $lblHCAllEmployees)   -replace '^$','N/A'
    'HC\Specific People'           = (Get-LabelIdentity $lblHCSpecific)       -replace '^$','N/A'
}
foreach ($entry in $guidMap.GetEnumerator() | Sort-Object Name) {
    Write-Host ("    {0,-40} {1}" -f $entry.Key, $entry.Value) -ForegroundColor Yellow
}

if ($script:Errors.Count -gt 0) {
    Write-Host "`n  ERRORS encountered during deployment:" -ForegroundColor Red
    foreach ($err in $script:Errors) { Write-Host "    - $err" -ForegroundColor Red }
}
else {
    Write-Host "`n  No errors encountered." -ForegroundColor Green
}

if ($script:LicenseSkips.Count -gt 0) {
    Write-Host "`n  SKIPPED due to missing licenses:" -ForegroundColor Yellow
    $grouped = $script:LicenseSkips | Group-Object RequiredLicense
    foreach ($grp in $grouped) {
        Write-Host "`n    Required license: $($grp.Name)" -ForegroundColor Yellow
        foreach ($skip in $grp.Group) {
            Write-Host "      - [$($skip.Section)] $($skip.Feature)" -ForegroundColor DarkYellow
        }
    }
    Write-Host "`n  To enable skipped features, assign the listed licenses in the" -ForegroundColor Yellow
    Write-Host "  Microsoft 365 admin center, then re-run this script." -ForegroundColor Yellow
}
else {
    Write-Host "`n  All features deployed — no license gaps detected." -ForegroundColor Green
}

Write-Host "`n  NEXT STEPS (required before switching policies to Enforce mode):" -ForegroundColor Yellow
Write-Host "    1. Configure Endpoint DLP: approved browsers, service domains, restricted app groups." -ForegroundColor Yellow
Write-Host "    2. Populate ExceptIfRecipientDomainIs in DLP-03 with approved partner domains." -ForegroundColor Yellow
Write-Host "    3. Configure IRM policy indicators and priority user groups in the portal." -ForegroundColor Yellow
Write-Host "    4. Customize OME branding (EmailText, IntroductionText, PortalText)." -ForegroundColor Yellow
Write-Host "    5. Confirm Adaptive Protection is active (check IRM Settings > Adaptive Protection)." -ForegroundColor Yellow
Write-Host "`n============================================================`n" -ForegroundColor Cyan
#endregion
