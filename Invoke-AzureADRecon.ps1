#Requires -Version 5.1
<#
  ╔══════════════════════════════════════════════════════════════════════════╗
  ║       AzureAD-Recon  —  Entra ID / Azure AD Security Audit Tool       ║
  ║                      by  Harsh P  |  github.com/MrHarshvardhan                        ║
  ║              Community Edition  |  github.com/MrHarshvardhan                   ║
  ╚══════════════════════════════════════════════════════════════════════════╝

.SYNOPSIS
    AzureAD-Recon by Harsh P  |  github.com/MrHarshvardhan — Entra ID security audit via Microsoft Graph API.
    Covers all checks PingCastle performs on Entra ID plus additional modules.

.DESCRIPTION
    Authenticates to Microsoft Graph (interactive device code, app secret, or
    existing Connect-MgGraph session) and audits the Entra ID tenant for
    security misconfigurations. Generates a self-contained HTML report.

    NO data is sent anywhere. All queries are read-only.

.PARAMETER TenantId
    Azure AD / Entra ID Tenant ID (GUID or domain). Auto-detects if connected.

.PARAMETER ClientId
    App registration Client ID for service-principal auth.

.PARAMETER ClientSecret
    App registration Client Secret. Use with ClientId.
    Replace the placeholder '<client-secret>' with your secret.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-based auth (more secure than secret).

.PARAMETER UseDeviceCode
    Force device code interactive login even if existing session exists.

.PARAMETER OutputPath
    Directory for the HTML report. Defaults to current directory.

.PARAMETER SkipChecks
    Module names to skip. Valid values:
    Roles, Users, MFA, ConditionalAccess, Applications, GuestSettings,
    SecurityDefaults, PasswordPolicy, SSPR, Domains, PIM, SyncSettings

.EXAMPLE
    # Interactive login (device code)
    .\Invoke-AzureADRecon.ps1 -UseDeviceCode

.EXAMPLE
    # App-based (headless / CI)
    .\Invoke-AzureADRecon.ps1 -TenantId contoso.onmicrosoft.com `
                               -ClientId <app-id> `
                               -ClientSecret '<client-secret>'

.EXAMPLE
    # Use existing Connect-MgGraph session
    Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","Reports.Read.All"
    .\Invoke-AzureADRecon.ps1

.NOTES
    Required Graph API permissions (read-only, application or delegated):
      Directory.Read.All
      Policy.Read.All
      Reports.Read.All
      AuditLog.Read.All
      IdentityRiskyUser.Read.All  (optional — for Identity Protection checks)
      RoleManagement.Read.All
      Application.Read.All
      UserAuthenticationMethod.Read.All
#>

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  QUICK CREDENTIAL SETUP                                                ║
# ╠══════════════════════════════════════════════════════════════════════════╣
# ║  Option A — Interactive login (easiest):                               ║
# ║    .\Invoke-AzureADRecon.ps1 -UseDeviceCode                            ║
# ║                                                                        ║
# ║  Option B — App registration (for automation):                         ║
# ║    .\Invoke-AzureADRecon.ps1 -TenantId contoso.com                     ║
# ║                               -ClientId  <app-guid>                   ║
# ║                               -ClientSecret '<client-secret>'         ║
# ║                                                                        ║
# ║  Option C — Existing MgGraph session:                                  ║
# ║    Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All",...  ║
# ║    .\Invoke-AzureADRecon.ps1                                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝

[CmdletBinding()]
param(
    [string]$TenantId              = '',
    [string]$ClientId              = '',
    [string]$ClientSecret          = '',      # Replace <client-secret>
    [string]$CertificateThumbprint = '',
    [switch]$UseDeviceCode,
    [switch]$OpenBrowser,
    [string]$OutputPath            = (Get-Location).Path,
    [string[]]$SkipChecks          = @()
)

$ErrorActionPreference = 'SilentlyContinue'
$StartTime = Get-Date

#region ── Helpers ────────────────────────────────────────────────────────────

function Write-Status { param([string]$Msg,[string]$Color='Cyan')
    Write-Host "  [*] $Msg" -ForegroundColor $Color }
function Write-OK     { param([string]$Msg)
    Write-Host "  [+] $Msg" -ForegroundColor Green }
function Open-BrowserUrl {
    param([string]$Url)
    try {
        if ($IsWindows -or $env:OS -eq 'Windows_NT') {
            Start-Process $Url
        } elseif ($IsMacOS) {
            & open $Url 2>$null
        } else {
            & xdg-open $Url 2>$null
        }
        Write-OK "Browser opened — complete sign-in then return here"
    } catch {
        Write-Warn "Could not open browser automatically — open the URL above manually"
    }
}
function Write-Warn   { param([string]$Msg)
    Write-Host "  [!] $Msg" -ForegroundColor Yellow }

function HE([string]$s) {
    [System.Web.HttpUtility]::HtmlEncode($s)
}

$Script:Findings      = [System.Collections.Generic.List[hashtable]]::new()

# MITRE ATT&CK TTP mapping for Azure AD / Entra ID findings
$Script:MitreTTPMap = @{
    'AZ-SecurityDefaults'     = 'T1078.004'
    'AZ-TooManyGlobalAdmins'  = 'T1078.004'
    'AZ-SPInPrivRole'         = 'T1078.004'
    'AZ-GuestInPrivRole'      = 'T1078.004'
    'AZ-AdminNoMFA'           = 'T1078.004'
    'AZ-UserMFALow'           = 'T1078.004'
    'AZ-NoCA'                 = 'T1078.004'
    'AZ-LegacyAuth'           = 'T1078.004'
    'AZ-NoMFAPolicy'          = 'T1078.004'
    'AZ-NoBreakGlass'         = 'T1078.003'
    'AZ-LongLivedSecret'      = 'T1552.001'
    'AZ-HighPrivApp'          = 'T1528'
    'AZ-GuestInviteEveryone'  = 'T1078.004'
    'AZ-GuestAsMember'        = 'T1078.004'
    'AZ-StaleGuests'          = 'T1078.004'
    'AZ-SMSAuth'              = 'T1621'
    'AZ-NoNamedLocation'      = 'T1078.004'
    'AZ-SyncStale'            = 'T1078.004'
    'AZ-PwdSyncStale'         = 'T1003.006'
    'AZ-PTAAgent'             = 'T1078.004'
    'AZ-NoPIM'                = 'T1078.004'
    'AZ-PIMNotUsed'           = 'T1078.004'
    'AZ-ConfirmedCompromised' = 'T1078.004'
    'AZ-HighRiskUsers'        = 'T1078.004'
    'AZ-FederatedDomain'      = 'T1199'
    'AZ-PwdNeverExpires'      = 'T1078.004'
    'AZ-StaleUser'            = 'T1078.004'
    'AZ-PwdNeverExpiresUser'  = 'T1078.004'
    'AZ-DisabledUserLicensed' = 'T1078.004'
    'AZ-OAuthConsent'         = 'T1528'
    'AZ-StaleDevice'          = 'T1078.004'
    'AZ-NonCompliantDevice'   = 'T1078.004'
    'AZ-SSPRWeakMethod'       = 'T1621'
    'AZ-SyncedAdmin'          = 'T1078.004'
    'AZ-NoSignInFrequency'    = 'T1078.004'
    'AZ-SPExpiredCert'        = 'T1552.001'
    'AZ-OpenGroupCreation'    = 'T1136.001'
    'AZ-CrossTenantInbound'   = 'T1199'
}
$Script:FailedModules = [System.Collections.Generic.List[hashtable]]::new()
$Script:Token         = $null
$Script:TenantData    = @{}

function Add-Finding {
    param([string]$Category,[string]$RuleId,[string]$Title,
          [string]$Risk,[string]$Detail,[string]$Remediation,[object]$Data=$null)
    $Script:Findings.Add(@{
        Category=$Category; RuleId=$RuleId; Title=$Title
        Risk=$Risk; Detail=$Detail; Remediation=$Remediation; Data=$Data
    })
}

function Get-GraphToken {
    # Method 1: existing Microsoft.Graph module session
    try {
        $ctx = Get-MgContext -ErrorAction Stop
        if ($ctx) {
            Write-OK "Using existing Microsoft.Graph session (Account: $($ctx.Account))"
            $Script:TenantData['TenantId'] = $ctx.TenantId
            return 'MgGraph'
        }
    } catch {}

    # Method 2: App secret (client credentials flow)
    if ($ClientId -ne '' -and $ClientSecret -ne '' -and $ClientSecret -ne '<client-secret>') {
        Write-Status "Authenticating via client credentials..."
        $body = @{
            grant_type    = 'client_credentials'
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = 'https://graph.microsoft.com/.default'
        }
        $tid = if ($TenantId) { $TenantId } else { 'common' }
        $resp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" `
                                  -Method POST -Body $body -ContentType 'application/x-www-form-urlencoded'
        if ($resp.access_token) {
            $Script:Token = $resp.access_token
            Write-OK "Authenticated via client credentials"

            # Decode tenant ID from token
            $parts   = $resp.access_token.Split('.')
            $payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[1].PadRight($parts[1].Length + (4 - $parts[1].Length % 4) % 4, '=')))
            $claims  = $payload | ConvertFrom-Json
            $Script:TenantData['TenantId'] = $claims.tid
            return 'Token'
        }
    }

    # Method 3: Device code flow
    if ($UseDeviceCode -or ($ClientId -eq '')) {
        Write-Status "Starting device code authentication..."
        $tid      = if ($TenantId) { $TenantId } else { 'common' }
        # Use well-known Azure PowerShell app ID for device code
        $appId    = '1950a258-227b-4e31-a9cf-717495945fc2'
        $dcResp   = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tid/oauth2/v2.0/devicecode" `
                    -Method POST -Body @{ client_id=$appId; scope='https://graph.microsoft.com/Directory.Read.All https://graph.microsoft.com/Policy.Read.All https://graph.microsoft.com/Reports.Read.All https://graph.microsoft.com/AuditLog.Read.All https://graph.microsoft.com/RoleManagement.Read.All https://graph.microsoft.com/Application.Read.All https://graph.microsoft.com/UserAuthenticationMethod.Read.All offline_access' }
        Write-Host ""
        Write-Host "  $($dcResp.message)" -ForegroundColor Yellow
        Write-Host ""
        if ($OpenBrowser) { Open-BrowserUrl "https://microsoft.com/devicelogin" }

        $deadline = (Get-Date).AddSeconds($dcResp.expires_in)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $dcResp.interval
            $tokenResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" `
                         -Method POST -Body @{
                             grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
                             client_id   = $appId
                             device_code = $dcResp.device_code
                         } -ErrorAction SilentlyContinue
            if ($tokenResp.access_token) {
                $Script:Token = $tokenResp.access_token
                $parts   = $tokenResp.access_token.Split('.')
                $payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[1].PadRight($parts[1].Length + (4 - $parts[1].Length % 4) % 4, '=')))
                $claims  = $payload | ConvertFrom-Json
                $Script:TenantData['TenantId'] = $claims.tid
                Write-OK "Authenticated via device code"
                return 'Token'
            }
        }
        throw "Device code authentication timed out"
    }

    throw "No authentication method succeeded. Use -UseDeviceCode or provide -ClientId/-ClientSecret."
}

function Invoke-Graph {
    param([string]$Uri, [string]$Method = 'GET', [hashtable]$Body = $null)
    try {
        if ($Script:Token) {
            $headers = @{ Authorization = "Bearer $Script:Token" }
            if ($Body) {
                return Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method `
                       -Body ($Body | ConvertTo-Json) -ContentType 'application/json'
            }
            return Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method
        } else {
            # Use Microsoft.Graph module cmdlets
            return Invoke-MgGraphRequest -Uri $Uri -Method $Method -OutputType PSObject
        }
    } catch {
        Write-Verbose "Graph call failed: $Uri — $_"
        return $null
    }
}

# Get all pages from a Graph list endpoint
function Get-GraphAll {
    param([string]$Uri)
    $results = [System.Collections.Generic.List[object]]::new()
    $next    = $Uri
    $page    = 0
    while ($next -and $page -lt 50) {
        $resp = Invoke-Graph -Uri $next
        if (-not $resp) { break }
        if ($resp.value) { $results.AddRange($resp.value) }
        $next = $resp.'@odata.nextLink'
        $page++
    }
    return $results
}

#endregion

#region ── CHECK: Tenant Info ─────────────────────────────────────────────────

function Invoke-CheckTenantInfo {
    Write-Status "Collecting tenant information..."

    $org = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/organization'
    if ($org -and $org.value -and $org.value.Count -gt 0) {
        $t = $org.value[0]
        $Script:TenantData['Name']            = $t.displayName
        $Script:TenantData['TenantId']        = $t.id
        $Script:TenantData['Created']         = $t.createdDateTime
        $Script:TenantData['Domains']         = @($t.verifiedDomains | ForEach-Object { $_.name })
        $Script:TenantData['AssignedPlans']   = @($t.assignedPlans | Where-Object { $_.capabilityStatus -eq 'Enabled' } | ForEach-Object { $_.service })
        $Script:TenantData['HasAADP2']        = ($Script:TenantData['AssignedPlans'] -match 'AADPremiumService') -or
                                                 ($t.assignedPlans | Where-Object { $_.service -match 'AADPremiumService' -and $_.capabilityStatus -eq 'Enabled' }).Count -gt 0

        # Check for non-default initial domain only (federated domains = higher risk)
        $federatedDomains = @($t.verifiedDomains | Where-Object { $_.capabilities -contains 'Federated' })
        if ($federatedDomains.Count -gt 0) {
            $Script:TenantData['FederatedDomains'] = @($federatedDomains | ForEach-Object { $_.name })
        }

        Write-OK "Tenant: $($t.displayName) ($($t.id))"
    }

    # Security defaults status
    $secDef = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    if ($secDef) {
        $Script:TenantData['SecurityDefaults'] = $secDef.isEnabled
        if (-not $secDef.isEnabled) {
            # Only flag if no CA policies exist (might be intentional with CA policies)
            $caPolicies = Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
            if ($caPolicies.Count -eq 0) {
                Add-Finding -Category 'TenantConfig' -RuleId 'AZ-SecurityDefaults' `
                    -Title 'Security Defaults disabled and no Conditional Access policies found' `
                    -Risk 'Critical' `
                    -Detail 'Security Defaults enforce MFA, block legacy auth, and protect privileged accounts. With no CA policies as a replacement, the tenant has no baseline authentication protections.' `
                    -Remediation 'Either re-enable Security Defaults or implement equivalent Conditional Access policies covering: MFA for admins, MFA for all users, block legacy auth.'
            }
        }
    }
}

#endregion

#region ── CHECK: Privileged Roles ────────────────────────────────────────────

$Script:GlobalAdmins = @()

function Invoke-CheckPrivilegedRoles {
    Write-Status "Checking privileged role assignments..."

    # Get all role definitions
    $roleDefs = Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName,roleTemplateId'

    $dangerRoles = @{
        '62e90394-69f5-4237-9190-012177145e10' = @{ Name='Global Administrator';         Risk='Critical' }
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = @{ Name='Privileged Authentication Administrator'; Risk='Critical' }
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = @{ Name='Privileged Role Administrator';   Risk='Critical' }
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = @{ Name='Application Administrator';        Risk='High' }
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' = @{ Name='Authentication Administrator';     Risk='High' }
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = @{ Name='Security Administrator';           Risk='High' }
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = @{ Name='SharePoint Administrator';         Risk='High' }
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = @{ Name='Exchange Administrator';           Risk='High' }
        '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = @{ Name='Hybrid Identity Administrator';    Risk='High' }
        '17315797-102d-40b4-93e0-432062caca18' = @{ Name='Compliance Administrator';         Risk='Medium' }
        '75941009-915a-4869-abe7-691bff18279e' = @{ Name='Helpdesk Administrator';           Risk='Medium' }
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = @{ Name='Helpdesk Administrator (alt)';    Risk='Medium' }
        'b0f54661-2d74-4c50-afa3-1ec803f12efe' = @{ Name='Billing Administrator';            Risk='Medium' }
        '4a5d8f65-41da-4de4-8968-e035b65339cf' = @{ Name='Teams Administrator';              Risk='Medium' }
        'f70938a0-fc10-4177-9e90-2178f8765737' = @{ Name='Intune Administrator';             Risk='Medium' }
        '3a2c62db-5318-420d-8d74-23affee5d9d5' = @{ Name='Intune Service Administrator';    Risk='Medium' }
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = @{ Name='User Administrator';              Risk='High' }
        '966707d0-3269-4727-9be2-8c3a10f19b9d' = @{ Name='Password Administrator';          Risk='High' }
        '7495fdc4-34c4-4d15-a289-98788ce399fd' = @{ Name='Azure DevOps Administrator';      Risk='Medium' }
        'be2f45a1-457d-42af-a067-6ec1fa63bc45' = @{ Name='External Identity Provider Admin';Risk='High' }
        '9360feb5-f418-4baa-8175-e2a00bac4301' = @{ Name='Directory Writers';               Risk='Medium' }
        '158c047a-c907-4556-b7ef-446551a6b5f7' = @{ Name='Cloud Application Administrator'; Risk='High' }
        '5d6b6bb7-de71-4623-b4af-96380a352509' = @{ Name='Security Reader';                 Risk='Low' }
        '3d762c5a-1b6c-493f-843e-55a3b42923d4' = @{ Name='Teams Communications Admin';      Risk='Low' }
    }

    $globalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
    $allPrivMembers        = [System.Collections.Generic.List[hashtable]]::new()
    $gaMembers             = [System.Collections.Generic.List[string]]::new()

    foreach ($role in $roleDefs) {
        $tmpl    = $role.roleTemplateId
        $rolInfo = $dangerRoles[$tmpl]
        if (-not $rolInfo) { continue }

        $members = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members?`$select=id,displayName,userPrincipalName,userType,accountEnabled"
        foreach ($m in $members) {
            $allPrivMembers.Add(@{ Role=$rolInfo.Name; Risk=$rolInfo.Risk; User=$m.displayName; UPN=$m.userPrincipalName; Type=$m.userType; Enabled=$m.accountEnabled }) | Out-Null
            if ($tmpl -eq $globalAdminTemplateId) {
                $gaMembers.Add($m.userPrincipalName) | Out-Null
            }
        }
    }

    $Script:GlobalAdmins = @($gaMembers)
    $gaCount = $gaMembers.Count

    Write-OK "Global Admins: $gaCount"

    # Too many Global Admins
    if ($gaCount -eq 0) {
        Add-Finding -Category 'Roles' -RuleId 'AZ-NoGlobalAdmin' `
            -Title 'No Global Administrator found — or insufficient permissions to read' `
            -Risk 'Critical' `
            -Detail 'No Global Administrator accounts were detected. Either the tenant has no GA (misconfiguration) or the audit account lacks RoleManagement.Read.All.' `
            -Remediation 'Verify audit account has Directory.Read.All and RoleManagement.Read.All permissions.'
    } elseif ($gaCount -gt 5) {
        Add-Finding -Category 'Roles' -RuleId 'AZ-TooManyGlobalAdmins' `
            -Title "Too many Global Administrators: $gaCount (recommended: 2-4)" `
            -Risk (if ($gaCount -gt 10) { 'Critical' } else { 'High' }) `
            -Detail "Microsoft recommends fewer than 5 Global Admins. Each GA can make any tenant-wide change. With $gaCount GAs, the blast radius of any single compromise is the entire tenant." `
            -Remediation 'Reduce Global Admin count to 2-4. Replace with least-privilege roles (e.g. User Admin, Security Admin). Use PIM for just-in-time elevation.' `
            -Data @($gaMembers)
    }

    # Service principals / apps in privileged roles
    $spInRoles = $allPrivMembers | Where-Object { $_.Type -eq 'servicePrincipal' -or ($_.UPN -and $_.UPN -notmatch '@') }
    if ($spInRoles.Count -gt 0) {
        Add-Finding -Category 'Roles' -RuleId 'AZ-SPInPrivRole' `
            -Title "$($spInRoles.Count) Service Principal(s) / Managed Identity in privileged roles" `
            -Risk 'Critical' `
            -Detail 'Applications and managed identities in privileged directory roles represent non-interactive attack surfaces. A compromised app credential = persistent admin access with no MFA.' `
            -Remediation 'Audit each SP in privileged roles. Replace with least-privilege application permissions. Use Managed Identities with minimal roles.' `
            -Data $spInRoles
    }

    # Guest users in privileged roles
    $guestsInRoles = $allPrivMembers | Where-Object { $_.Type -eq 'Guest' }
    if ($guestsInRoles.Count -gt 0) {
        Add-Finding -Category 'Roles' -RuleId 'AZ-GuestInPrivRole' `
            -Title "$($guestsInRoles.Count) Guest account(s) in privileged roles" `
            -Risk 'Critical' `
            -Detail 'Guest accounts from external tenants in privileged roles are high-risk. Their home tenant controls their authentication, not yours.' `
            -Remediation 'Remove all guest accounts from privileged roles. If vendor access is needed, use delegated access or Azure Lighthouse instead.' `
            -Data $guestsInRoles
    }

    $Script:AllPrivMembers = $allPrivMembers
}

#endregion

#region ── CHECK: MFA Status ──────────────────────────────────────────────────

function Invoke-CheckMFA {
    Write-Status "Checking MFA registration for privileged accounts..."

    # Check MFA registration via authentication methods (requires UserAuthenticationMethod.Read.All)
    $mfaNotRegistered = [System.Collections.Generic.List[string]]::new()

    foreach ($ga in ($Script:GlobalAdmins | Select-Object -First 20)) {
        # Get user ID first
        $user = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/users/$($ga)?`$select=id,displayName,userPrincipalName"
        if (-not $user) { continue }

        $methods = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods"
        # If only passwordAuthenticationMethod present -> no MFA
        $mfaMethods = $methods | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' }
        if ($mfaMethods.Count -eq 0) {
            $mfaNotRegistered.Add($ga) | Out-Null
        }
    }

    if ($mfaNotRegistered.Count -gt 0) {
        Add-Finding -Category 'Users' -RuleId 'AZ-AdminNoMFA' `
            -Title "$($mfaNotRegistered.Count) Global Admin(s) have NO MFA method registered" `
            -Risk 'Critical' `
            -Detail 'Global Administrators without MFA can be compromised via password spray, credential stuffing, or phishing — with no second factor to stop the attack. This is the single highest-impact finding in any Entra ID audit.' `
            -Remediation 'Enforce MFA for ALL admins via Conditional Access. Require phishing-resistant MFA (FIDO2/Windows Hello) for Global Admins specifically.' `
            -Data @($mfaNotRegistered)
    } else {
        Write-OK "Global Admin MFA: all checked accounts have MFA registered"
    }

    # Check MFA registration report for all users
    try {
        $regReport = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethodsUserRegistrationDetails?`$top=999"
        if ($regReport -and $regReport.value) {
            $noMfa     = @($regReport.value | Where-Object { -not $_.isMfaRegistered -and $_.isAdmin -eq $false })
            $adminNoMfa= @($regReport.value | Where-Object { -not $_.isMfaRegistered -and $_.isAdmin -eq $true })
            $total     = $regReport.value.Count
            $noMfaPct  = if ($total -gt 0) { [Math]::Round(($noMfa.Count / $total) * 100) } else { 0 }

            if ($adminNoMfa.Count -gt 0) {
                Add-Finding -Category 'Users' -RuleId 'AZ-AdminNoMFA-All' `
                    -Title "$($adminNoMfa.Count) admin account(s) without MFA registered (tenant-wide)" `
                    -Risk 'Critical' `
                    -Detail 'Admin accounts without MFA registration detected via the authentication methods report.' `
                    -Remediation 'Enforce MFA registration for all admins via Conditional Access. Use nudge policies to drive registration.' `
                    -Data @($adminNoMfa | Select-Object -First 15 | ForEach-Object { $_.userPrincipalName })
            }

            if ($noMfaPct -gt 20) {
                Add-Finding -Category 'Users' -RuleId 'AZ-UserMFALow' `
                    -Title "$noMfaPct% of users ($($noMfa.Count)) have no MFA method registered" `
                    -Risk (if ($noMfaPct -gt 50) { 'High' } else { 'Medium' }) `
                    -Detail "Low MFA adoption means most user accounts are vulnerable to password attacks. Phishing campaigns targeting non-MFA users can compromise the tenant via Azure AD Connect or other paths." `
                    -Remediation 'Create a CA policy requiring MFA for all users. Use the MFA registration campaign feature to nudge users. Set a compliance deadline.'
            }
        }
    } catch {}
}

#endregion

#region ── CHECK: Conditional Access ──────────────────────────────────────────

function Invoke-CheckConditionalAccess {
    Write-Status "Analysing Conditional Access policies..."

    $caPolicies = Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    Write-OK "Conditional Access: $($caPolicies.Count) policies found"

    $enabledPolicies = @($caPolicies | Where-Object { $_.state -eq 'enabled' })
    $reportOnly      = @($caPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

    if ($enabledPolicies.Count -eq 0 -and -not $Script:TenantData['SecurityDefaults']) {
        Add-Finding -Category 'ConditionalAccess' -RuleId 'AZ-NoCA' `
            -Title 'No enabled Conditional Access policies and Security Defaults disabled' `
            -Risk 'Critical' `
            -Detail 'The tenant has no authentication controls. Any valid credential provides unrestricted access from any location, any device, without MFA.' `
            -Remediation 'Implement baseline CA policies: (1) Require MFA for admins, (2) Require MFA for all users, (3) Block legacy authentication, (4) Require compliant device for sensitive apps.'
        return
    }

    if ($reportOnly.Count -gt 0) {
        Add-Finding -Category 'ConditionalAccess' -RuleId 'AZ-CAReportOnly' `
            -Title "$($reportOnly.Count) CA policies are in report-only mode (not enforced)" `
            -Risk 'Medium' `
            -Detail 'Report-only policies log what would happen but do not enforce authentication controls. They provide no protection.' `
            -Remediation 'Review report-only policies. If they have been in report mode for > 30 days with acceptable impact, move to enabled mode.'
    }

    # Check for legacy authentication block policy
    $legacyBlocked = $enabledPolicies | Where-Object {
        $_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
        $_.conditions.clientAppTypes -contains 'other' -or
        ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -and
         $_.grantControls.builtInControls -contains 'block')
    }

    if ($legacyBlocked.Count -eq 0) {
        Add-Finding -Category 'ConditionalAccess' -RuleId 'AZ-LegacyAuth' `
            -Title 'No CA policy found that blocks legacy authentication protocols' `
            -Risk 'Critical' `
            -Detail 'Legacy auth (Basic Auth, SMTP AUTH, POP3, IMAP, ActiveSync without modern auth) bypasses MFA entirely. Over 99% of password spray attacks use legacy auth endpoints because they cannot be MFA-protected.' `
            -Remediation 'Create CA policy: Conditions > Client apps = Exchange ActiveSync + Other, Grant = Block. Test with report-only mode first. Ensure all apps support modern authentication.'
    } else {
        Write-OK "Legacy auth: blocked by CA policy"
    }

    # Check if all users are covered by at least one MFA policy
    $mfaPolicies = $enabledPolicies | Where-Object {
        $_.grantControls.builtInControls -contains 'mfa' -and
        ($_.conditions.users.includeUsers -contains 'All' -or
         $_.conditions.users.includeGroups.Count -gt 0)
    }

    if ($mfaPolicies.Count -eq 0) {
        Add-Finding -Category 'ConditionalAccess' -RuleId 'AZ-NoMFAPolicy' `
            -Title 'No Conditional Access policy enforces MFA for all users' `
            -Risk 'High' `
            -Detail 'Without a broad MFA enforcement policy, users who are not individually targeted by other MFA policies can authenticate without MFA.' `
            -Remediation 'Create a baseline CA policy: All users > All cloud apps > Require MFA. Exclude break-glass accounts. Use named locations to exempt trusted IPs if needed.'
    }

    # Policies without any exclusion for break-glass accounts
    $policiesExcludingNone = $enabledPolicies | Where-Object {
        $_.conditions.users.includeUsers -contains 'All' -and
        $_.conditions.users.excludeUsers.Count -eq 0 -and
        $_.conditions.users.excludeGroups.Count -eq 0
    }

    if ($policiesExcludingNone.Count -gt 0) {
        Add-Finding -Category 'ConditionalAccess' -RuleId 'AZ-NoBreakGlass' `
            -Title "$($policiesExcludingNone.Count) CA policy/policies have no exclusions (break-glass risk)" `
            -Risk 'Medium' `
            -Detail 'CA policies with no exclusions will lock out break-glass (emergency) accounts. If the CA infrastructure fails or all compliant devices are unavailable, recovery may be impossible.' `
            -Remediation 'Create a dedicated break-glass group. Exclude it from all blocking CA policies. Store credentials in a physical safe. Monitor break-glass usage with alerts.'
    }

    $Script:TenantData['CACount']       = $enabledPolicies.Count
    $Script:TenantData['LegacyBlocked'] = ($legacyBlocked.Count -gt 0)
}

#endregion

#region ── CHECK: Application Security ────────────────────────────────────────

function Invoke-CheckApplications {
    Write-Status "Auditing app registrations and enterprise apps..."

    $now = Get-Date

    # App registrations with expiring/expired secrets
    $apps = Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,displayName,passwordCredentials,keyCredentials,appId'
    $expiredSecrets  = [System.Collections.Generic.List[hashtable]]::new()
    $expiringSecrets = [System.Collections.Generic.List[hashtable]]::new()
    $noExpiry        = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($app in $apps) {
        foreach ($secret in $app.passwordCredentials) {
            $expiry = [datetime]$secret.endDateTime
            if ($expiry -lt $now) {
                $expiredSecrets.Add(@{ App=$app.displayName; Hint=$secret.hint; Expiry=$expiry }) | Out-Null
            } elseif ($expiry -lt $now.AddDays(30)) {
                $expiringSecrets.Add(@{ App=$app.displayName; Hint=$secret.hint; Expiry=$expiry; DaysLeft=([int]($expiry-$now).TotalDays) }) | Out-Null
            }
            # No expiry = very long-lived secret
            if ($secret.endDateTime -match '2299|9999') {
                $noExpiry.Add(@{ App=$app.displayName; Hint=$secret.hint }) | Out-Null
            }
        }
    }

    if ($noExpiry.Count -gt 0) {
        Add-Finding -Category 'Applications' -RuleId 'AZ-LongLivedSecret' `
            -Title "$($noExpiry.Count) app registration(s) with non-expiring or 200+ year secrets" `
            -Risk 'High' `
            -Detail 'Long-lived client secrets never rotate, meaning a leaked secret provides permanent access. Secrets should expire within 1-2 years maximum.' `
            -Remediation 'Set expiry on all app secrets. Prefer certificate credentials over secrets. Consider Managed Identities which have no credential to manage.' `
            -Data ($noExpiry | Select-Object -First 15)
    }

    # Service principals with high-privilege application permissions to MS Graph
    $dangerPerms = @{
        'df021288-bdef-4463-88db-98f22de89214' = 'User.ReadWrite.All (application)'
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' = 'RoleManagement.ReadWrite.Directory (application)'
        '741f803b-c850-494e-b5df-cde7c675a1ca' = 'User.ReadWrite.All'
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' = 'Application.ReadWrite.All'
        '06b708a9-e830-4db3-a914-8e69da51d44f' = 'AppRoleAssignment.ReadWrite.All'
        '62a82d76-70ea-41e2-9197-370581804d09' = 'Group.ReadWrite.All'
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7' = 'Directory.ReadWrite.All'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application.Read.All'
    }

    $sps = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=servicePrincipalType eq 'Application'&`$select=id,displayName,appId"
    $highPrivApps = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($sp in ($sps | Select-Object -First 100)) {
        $grants = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments"
        $highGrants = $grants | Where-Object { $dangerPerms[$_.appRoleId] }
        if ($highGrants.Count -gt 0) {
            $highPrivApps.Add(@{
                App    = $sp.displayName
                Perms  = ($highGrants | ForEach-Object { $dangerPerms[$_.appRoleId] } | Sort-Object -Unique) -join ', '
            }) | Out-Null
        }
    }

    if ($highPrivApps.Count -gt 0) {
        Add-Finding -Category 'Applications' -RuleId 'AZ-HighPrivApp' `
            -Title "$($highPrivApps.Count) app(s) with high-privilege application Graph permissions" `
            -Risk 'High' `
            -Detail 'Applications with permissions like Directory.ReadWrite.All or RoleManagement.ReadWrite.Directory can modify the entire tenant. A compromised app = full tenant takeover.' `
            -Remediation 'Audit each application. Remove unnecessary permissions. Apply least-privilege. Use delegated permissions where possible. Require admin consent review for high-privilege grants.' `
            -Data ($highPrivApps | Select-Object -First 10)
    }

    Write-OK "Applications: $($apps.Count) app registrations, $($highPrivApps.Count) with high privileges"
}

#endregion

#region ── CHECK: Guest User Settings ─────────────────────────────────────────

function Invoke-CheckGuestSettings {
    Write-Status "Checking guest and external collaboration settings..."

    $policy = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    if ($policy) {
        $guestInvite   = $policy.allowInvitesFrom
        $guestAccess   = $policy.guestUserRoleId
        $defaultUserRole = $policy.defaultUserRolePermissions

        # allowInvitesFrom: none=most secure, adminsAndGuestInviters=OK, adminsGuestInvitersAndAllMembers=risky, everyone=critical
        if ($guestInvite -eq 'everyone') {
            Add-Finding -Category 'GuestSettings' -RuleId 'AZ-GuestInviteEveryone' `
                -Title 'Any user can invite external guests (allowInvitesFrom = everyone)' `
                -Risk 'High' `
                -Detail 'Any internal user can invite external parties as guests. This creates an uncontrolled expansion of external identities with directory read access.' `
                -Remediation 'Set allowInvitesFrom = adminsAndGuestInviters or none. Control guest invitations via approved processes only.'
        } elseif ($guestInvite -eq 'adminsGuestInvitersAndAllMembers') {
            Add-Finding -Category 'GuestSettings' -RuleId 'AZ-GuestInviteAllMembers' `
                -Title 'All members can invite external guests' `
                -Risk 'Medium' `
                -Detail 'All internal members can invite guests, not just designated guest inviters. This risks uncontrolled external access proliferation.' `
                -Remediation 'Restrict to adminsAndGuestInviters or create a governed request process via Entitlement Management.'
        }

        # Guest role: guestUserRoleId 10dae51f = RestrictedGuest (most restrictive), 2af84b1e = Guest, bf394140 = Member (most permissive)
        if ($guestAccess -eq 'bf394140-e1a0-4b47-b1ab-bffd5fd6afa0') {
            Add-Finding -Category 'GuestSettings' -RuleId 'AZ-GuestAsMember' `
                -Title 'Guest users have same permissions as members (guestUserRoleId = Member)' `
                -Risk 'High' `
                -Detail 'Guest users can enumerate all users, groups, and directory objects — the same as any internal member. External parties have full tenant visibility.' `
                -Remediation 'Set Guest User Access to "Guest users have limited access to properties and memberships" (Restricted Guest role).'
        }

        # Default user role — can users register apps?
        if ($defaultUserRole.allowedToCreateApps -eq $true) {
            Add-Finding -Category 'GuestSettings' -RuleId 'AZ-UsersCreateApps' `
                -Title 'Any user can register application registrations' `
                -Risk 'Medium' `
                -Detail 'Users can create app registrations that obtain API permissions. A malicious user could create an app that other users consent to, granting access to their mailboxes or files.' `
                -Remediation 'Disable: "Users can register applications" in Entra ID > User Settings. Enforce admin consent workflow for new app registrations.'
        }
    }

    # Count guest users
    $guests = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime"
    $activeGuests  = @($guests | Where-Object { $_.accountEnabled -eq $true })
    $staleGuests   = @($activeGuests | Where-Object {
        $created = if ($_.createdDateTime) { [datetime]$_.createdDateTime } else { $null }
        $created -and ([datetime]::Now - $created).TotalDays -gt 365
    })

    $Script:TenantData['GuestCount'] = $guests.Count
    Write-OK "Guest users: $($guests.Count) total ($($activeGuests.Count) enabled)"

    if ($staleGuests.Count -gt 0) {
        Add-Finding -Category 'GuestSettings' -RuleId 'AZ-StaleGuests' `
            -Title "$($staleGuests.Count) guest account(s) older than 1 year (potentially stale)" `
            -Risk 'Low' `
            -Detail 'Long-standing guest accounts that are no longer active represent unnecessary external access to the tenant.' `
            -Remediation 'Implement guest access reviews (Entra ID Governance > Access Reviews). Remove guests who no longer require access. Automate expiry.'
    }
}

#endregion

#region ── CHECK: SSPR and Authentication Methods ─────────────────────────────

function Invoke-CheckAuthMethods {
    Write-Status "Checking authentication methods and SSPR..."

    # SSPR policy
    $sspr = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    if ($sspr) {
        $smsMethods = $sspr.authenticationMethodConfigurations | Where-Object { $_.id -eq 'sms' }
        if ($smsMethods -and $smsMethods.state -eq 'enabled') {
            Add-Finding -Category 'AuthMethods' -RuleId 'AZ-SMSAuth' `
                -Title 'SMS-based authentication is enabled' `
                -Risk 'Medium' `
                -Detail 'SMS-based authentication (OTP via text) is vulnerable to SIM-swapping attacks and real-time phishing toolkits (Evilginx, Modlishka). It does not constitute phishing-resistant MFA.' `
                -Remediation 'Migrate users from SMS to phishing-resistant methods: FIDO2 security keys, Windows Hello for Business, or Certificate-Based Authentication.'
        }
    }

    # Named locations — check if no trusted named location defined
    $namedLocations = Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations'
    if ($namedLocations.Count -eq 0) {
        Add-Finding -Category 'ConditionalAccess' -RuleId 'AZ-NoNamedLocation' `
            -Title 'No named locations configured in Conditional Access' `
            -Risk 'Low' `
            -Detail 'Without named locations, CA policies cannot distinguish corporate network sign-ins from external/risky sign-ins for location-based policies.' `
            -Remediation 'Create named locations for trusted corporate IPs. Use in CA policies for context-aware access (e.g. skip MFA from trusted IPs, block from high-risk countries).'
    }
}

#endregion

#region ── CHECK: Hybrid Identity (AD Connect) ────────────────────────────────

function Invoke-CheckHybridIdentity {
    Write-Status "Checking hybrid identity and synchronisation settings..."

    # On-premises sync status
    $org = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/organization?$select=onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesLastPasswordSyncDateTime'
    if ($org -and $org.value) {
        $t = $org.value[0]
        $Script:TenantData['HybridSync'] = $t.onPremisesSyncEnabled

        if ($t.onPremisesSyncEnabled) {
            $lastSync = if ($t.onPremisesLastSyncDateTime) { [datetime]$t.onPremisesLastSyncDateTime } else { $null }
            if ($lastSync -and ([datetime]::Now - $lastSync).TotalHours -gt 4) {
                Add-Finding -Category 'HybridIdentity' -RuleId 'AZ-SyncStale' `
                    -Title "AAD Connect last sync: $([Math]::Round(([datetime]::Now - $lastSync).TotalHours)) hours ago" `
                    -Risk 'Medium' `
                    -Detail 'Azure AD Connect sync has not run recently. Stale sync may indicate the sync server is down, compromised, or misconfigured.' `
                    -Remediation 'Investigate the AAD Connect server health. Check the synchronization service manager logs. Ensure the sync server is monitored.'
            }

            # Password hash sync — check last password sync
            $lastPwdSync = if ($t.onPremisesLastPasswordSyncDateTime) { [datetime]$t.onPremisesLastPasswordSyncDateTime } else { $null }
            if ($lastPwdSync -and ([datetime]::Now - $lastPwdSync).TotalHours -gt 4) {
                Add-Finding -Category 'HybridIdentity' -RuleId 'AZ-PwdSyncStale' `
                    -Title 'Password hash synchronisation has not run in over 4 hours' `
                    -Risk 'Medium' `
                    -Detail 'Stale password hash sync means recent on-prem password changes are not reflected in Entra ID, breaking authentication for affected users.' `
                    -Remediation 'Check AAD Connect PHS configuration. Review Event Viewer on the sync server for errors.'
            }

            Write-OK "Hybrid sync: active (last sync: $lastSync)"
        }
    }

    # Check for PTA agents (Pass-Through Authentication)
    $ptaAgents = Get-GraphAll -Uri 'https://graph.microsoft.com/beta/onPremisesPublishingProfiles/provisioning/agents'
    if ($ptaAgents.Count -gt 0) {
        $inactiveAgents = @($ptaAgents | Where-Object { $_.status -ne 'active' })
        if ($inactiveAgents.Count -gt 0) {
            Add-Finding -Category 'HybridIdentity' -RuleId 'AZ-PTAAgent' `
                -Title "$($inactiveAgents.Count) Pass-Through Authentication agent(s) are inactive" `
                -Risk 'Medium' `
                -Detail 'Inactive PTA agents reduce authentication resilience. If all agents go offline, PTA authentication will fail.' `
                -Remediation 'Investigate and remediate inactive PTA agents. Deploy at least 3 agents for high availability. Monitor agent health.'
        }
    }
}

#endregion

#region ── CHECK: Privileged Identity Management ──────────────────────────────

function Invoke-CheckPIM {
    Write-Status "Checking Privileged Identity Management (PIM) configuration..."

    if (-not $Script:TenantData['HasAADP2']) {
        Add-Finding -Category 'Roles' -RuleId 'AZ-NoPIM' `
            -Title 'Azure AD P2 / Entra ID Governance not licensed — PIM not available' `
            -Risk 'Medium' `
            -Detail 'Without PIM, all privileged roles are permanently assigned. There is no just-in-time activation, approval workflow, or privileged access review capability.' `
            -Remediation 'License Entra ID P2 or Entra ID Governance. Implement PIM for all privileged roles. Move from permanent to eligible assignments.'
        return
    }

    # Check PIM role assignments — active permanent vs eligible
    try {
        $permAssignments = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId ne ''"
        $eligAssignments = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules"

        if ($permAssignments.Count -gt 0 -and $eligAssignments.Count -eq 0) {
            Add-Finding -Category 'Roles' -RuleId 'AZ-PIMNotUsed' `
                -Title 'PIM licensed but no eligible role assignments configured' `
                -Risk 'High' `
                -Detail "P2 license detected but all $($permAssignments.Count) role assignments are permanent (active). PIM is not being used for just-in-time access." `
                -Remediation 'Convert permanent role assignments to PIM eligible assignments. Require approval for Global Admin activation. Set maximum activation duration to 4-8 hours.'
        } elseif ($eligAssignments.Count -gt 0) {
            Write-OK "PIM: $($eligAssignments.Count) eligible assignments configured"
        }
    } catch {
        Write-Warn "PIM check requires additional permissions — skipping detailed PIM analysis"
    }
}

#endregion

#region ── CHECK: Risky Users and Sign-ins ────────────────────────────────────

function Invoke-CheckRiskyUsers {
    Write-Status "Checking Identity Protection risky users..."

    if (-not $Script:TenantData['HasAADP2']) {
        Write-OK "Identity Protection requires P2 license — skipping"
        return
    }

    $riskyUsers = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'&`$select=id,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime"

    $confirmed  = @($riskyUsers | Where-Object { $_.riskState -eq 'confirmedCompromised' })
    $atRiskHigh = @($riskyUsers | Where-Object { $_.riskLevel -eq 'high' -and $_.riskState -eq 'atRisk' })

    if ($confirmed.Count -gt 0) {
        Add-Finding -Category 'Users' -RuleId 'AZ-ConfirmedCompromised' `
            -Title "$($confirmed.Count) account(s) marked as Confirmed Compromised in Identity Protection" `
            -Risk 'Critical' `
            -Detail 'These accounts have been confirmed compromised (by Microsoft or the security team). They may be actively used by attackers.' `
            -Remediation 'Immediately: (1) Reset passwords + revoke sessions, (2) Review recent activity in sign-in logs, (3) Check for persistence (app consents, role assignments, forwarding rules), (4) Investigate root cause.' `
            -Data @($confirmed | ForEach-Object { $_.userPrincipalName })
    }

    if ($atRiskHigh.Count -gt 0) {
        Add-Finding -Category 'Users' -RuleId 'AZ-HighRiskUsers' `
            -Title "$($atRiskHigh.Count) user(s) flagged as high-risk by Identity Protection" `
            -Risk 'High' `
            -Detail 'Microsoft Identity Protection has detected high-confidence indicators of compromise (leaked credentials, impossible travel, malware-linked IPs).' `
            -Remediation 'Investigate each user. Create a CA policy requiring MFA + password change for high-risk users. Consider blocking sign-in pending investigation.' `
            -Data @($atRiskHigh | ForEach-Object { $_.userPrincipalName })
    }

    Write-OK "Risky users: $($confirmed.Count) confirmed, $($atRiskHigh.Count) high-risk"
}

#endregion

#region ── CHECK: Domain Federation Security ──────────────────────────────────

function Invoke-CheckDomains {
    Write-Status "Checking domain federation and authentication configuration..."

    $domains = Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,authenticationType,isVerified,isDefault,passwordValidityPeriodInDays,passwordNotificationWindowInDays,federationConfiguration'

    foreach ($domain in $domains) {
        # Federated domains that are no longer needed
        if ($domain.authenticationType -eq 'Federated') {
            Add-Finding -Category 'Domains' -RuleId 'AZ-FederatedDomain' `
                -Title "Domain '$($domain.id)' is federated" `
                -Risk 'Low' `
                -Detail 'Federated domains delegate authentication to an external IdP (AD FS, Okta, etc.). The external IdP becomes a high-value target — its compromise = tenant compromise. Verify this is intentional.' `
                -Remediation 'If no longer required, convert to managed (password hash sync) authentication via Convert-MsolDomainToStandard. Review AD FS security hardening.'
        }

        # Cloud password never expires
        if ($domain.passwordValidityPeriodInDays -eq 2147483647) {
            Add-Finding -Category 'Domains' -RuleId 'AZ-PwdNeverExpires' `
                -Title "Domain '$($domain.id)' cloud passwords set to never expire" `
                -Risk 'Low' `
                -Detail 'Cloud-only passwords that never expire accumulate breach risk over time. Microsoft recommends annual rotation at minimum for accounts without MFA.' `
                -Remediation 'Set PasswordValidityPeriodInDays to 365 or implement a Conditional Access policy requiring MFA (which compensates for non-expiring passwords per NIST SP 800-63B).'
        }
    }
}

#endregion

#region ── CHECK: User Inventory ──────────────────────────────────────────────

$Script:UserInventory = @()

function Invoke-CheckUserInventory {
    Write-Status "Collecting full user inventory and configuration issues..."

    $select = 'id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,passwordPolicies,assignedLicenses,onPremisesSyncEnabled,department,jobTitle,signInActivity'
    $users  = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999"

    $now = Get-Date

    $staleAccounts    = [System.Collections.Generic.List[hashtable]]::new()
    $pwdNeverExpires  = [System.Collections.Generic.List[hashtable]]::new()
    $disabledLicensed = [System.Collections.Generic.List[hashtable]]::new()
    $allUserRows      = [System.Collections.Generic.List[hashtable]]::new()

    $enabledCount = 0; $disabledCount = 0; $syncedCount = 0; $cloudCount = 0

    foreach ($u in $users) {
        if ($u.userType -eq 'Guest') { continue }

        $isEnabled  = $u.accountEnabled -eq $true
        $isSynced   = $u.onPremisesSyncEnabled -eq $true
        $isLicensed = $u.assignedLicenses -and $u.assignedLicenses.Count -gt 0
        $pwdNeverExp= $u.passwordPolicies -and ($u.passwordPolicies -match 'DisablePasswordExpiration')

        $lastSignInStr   = 'N/A (P1 required)'
        $daysSinceSignIn = $null
        if ($u.signInActivity -and $u.signInActivity.lastSignInDateTime) {
            $lastSignIn      = [datetime]$u.signInActivity.lastSignInDateTime
            $daysSinceSignIn = [int]($now - $lastSignIn).TotalDays
            $lastSignInStr   = $lastSignIn.ToString('yyyy-MM-dd')
        }

        if ($isEnabled)  { $enabledCount++  } else { $disabledCount++ }
        if ($isSynced)   { $syncedCount++   } else { $cloudCount++ }

        $issues = @()
        if ($daysSinceSignIn -and $daysSinceSignIn -gt 90) { $issues += "Stale (${daysSinceSignIn}d)" }
        if ($pwdNeverExp)                                   { $issues += 'PwdNeverExpires' }
        if (-not $isEnabled -and $isLicensed)               { $issues += 'DisabledButLicensed' }

        $allUserRows.Add(@{
            Name       = "$($u.displayName)"
            UPN        = "$($u.userPrincipalName)"
            Enabled    = if ($isEnabled) { 'Yes' } else { 'No' }
            Source     = if ($isSynced) { 'Synced' } else { 'Cloud' }
            LastSignIn = $lastSignInStr
            PwdExpires = if ($pwdNeverExp) { 'Never' } else { 'Normal' }
            Licensed   = if ($isLicensed) { 'Yes' } else { 'No' }
            Department = "$($u.department)"
            Issues     = if ($issues.Count -gt 0) { $issues -join '; ' } else { 'None' }
        }) | Out-Null

        if ($isEnabled -and $daysSinceSignIn -and $daysSinceSignIn -gt 90) {
            $staleAccounts.Add(@{
                Name      = "$($u.displayName)"
                UPN       = "$($u.userPrincipalName)"
                LastSignIn= $lastSignInStr
                DaysIdle  = $daysSinceSignIn
                Licensed  = if ($isLicensed) { 'Yes' } else { 'No' }
                Dept      = "$($u.department)"
            }) | Out-Null
        }

        if ($isEnabled -and $pwdNeverExp) {
            $pwdNeverExpires.Add(@{
                Name   = "$($u.displayName)"
                UPN    = "$($u.userPrincipalName)"
                Dept   = "$($u.department)"
                Source = if ($isSynced) { 'Synced' } else { 'Cloud' }
            }) | Out-Null
        }

        if (-not $isEnabled -and $isLicensed) {
            $disabledLicensed.Add(@{
                Name     = "$($u.displayName)"
                UPN      = "$($u.userPrincipalName)"
                Licenses = $u.assignedLicenses.Count
            }) | Out-Null
        }
    }

    $Script:UserInventory                = @($allUserRows)
    $Script:TenantData['TotalUsers']     = $users.Count
    $Script:TenantData['EnabledUsers']   = $enabledCount
    $Script:TenantData['DisabledUsers']  = $disabledCount
    $Script:TenantData['SyncedUsers']    = $syncedCount
    $Script:TenantData['CloudUsers']     = $cloudCount

    Write-OK "Users: $($users.Count) total ($enabledCount enabled, $disabledCount disabled, $syncedCount synced)"

    if ($staleAccounts.Count -gt 0) {
        Add-Finding -Category 'Users' -RuleId 'AZ-StaleUser' `
            -Title "$($staleAccounts.Count) enabled user account(s) with no sign-in for 90+ days" `
            -Risk 'Medium' `
            -Detail "Active accounts with no sign-in for over 90 days represent unnecessary attack surface. They can be targeted by credential stuffing or phishing without anyone noticing unusual activity. Sign-in data visibility requires Azure AD P1/P2 licensing." `
            -Remediation '1. Review each account with the manager — determine if still needed. 2. Disable accounts no longer in use via HR offboarding. 3. Implement Entra ID Lifecycle Workflows to automate stale account handling. 4. Remove licenses from stale accounts to reduce cost.' `
            -Data ($staleAccounts | Sort-Object DaysIdle -Descending)
    }

    if ($pwdNeverExpires.Count -gt 0) {
        Add-Finding -Category 'Users' -RuleId 'AZ-PwdNeverExpiresUser' `
            -Title "$($pwdNeverExpires.Count) user(s) have password set to never expire" `
            -Risk 'Low' `
            -Detail "Passwords that never expire accumulate breach risk over time — they may appear in data breach dumps from years ago. Cloud-only accounts specifically should have password expiration unless covered by a strong MFA Conditional Access policy (per NIST SP 800-63B)." `
            -Remediation '1. Set a domain password expiration policy. 2. As compensating control, ensure all affected accounts are covered by a MFA CA policy. 3. For service accounts, use Managed Identities instead. 4. Set PasswordValidityPeriodInDays = 365 on the domain.' `
            -Data ($pwdNeverExpires | Select-Object -First 50)
    }

    if ($disabledLicensed.Count -gt 0) {
        Add-Finding -Category 'Users' -RuleId 'AZ-DisabledUserLicensed' `
            -Title "$($disabledLicensed.Count) disabled account(s) still holding active licenses" `
            -Risk 'Medium' `
            -Detail "Disabled accounts with active licenses waste license spend and create a re-enablement risk — if an old account is accidentally re-enabled, it immediately gets full access without any review. This commonly happens when offboarding processes are incomplete." `
            -Remediation '1. Remove all licenses from disabled accounts immediately. 2. Implement a Lifecycle Workflow that removes licenses at account disable. 3. Review these accounts — some may be service accounts that need alternative management. 4. Consider deleting accounts older than 90 days post-disable.' `
            -Data $disabledLicensed
    }
}

#endregion

#region ── CHECK: OAuth2 Consent Grants ───────────────────────────────────────

function Invoke-CheckOAuthConsents {
    Write-Status "Auditing OAuth2 delegated permission grants (consent phishing surface)..."

    $dangerousScopes = @(
        'Mail.ReadWrite','Mail.Read','Mail.Send',
        'Files.ReadWrite.All','Files.Read.All',
        'Calendars.ReadWrite','Contacts.ReadWrite',
        'Directory.ReadWrite.All','Directory.Read.All',
        'User.ReadWrite.All','Group.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory',
        'MailboxSettings.ReadWrite','People.Read.All'
    )

    $grants = Get-GraphAll -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999'
    $riskyGrants = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($grant in $grants) {
        if (-not $grant.scope) { continue }
        $grantScopes = $grant.scope -split ' '
        $matched = @($grantScopes | Where-Object { $dangerousScopes -contains $_ })
        if ($matched.Count -eq 0) { continue }

        $spName = 'Unknown'
        if ($grant.clientId) {
            $sp = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($grant.clientId)?`$select=displayName"
            if ($sp -and $sp.displayName) { $spName = $sp.displayName }
        }

        $riskyGrants.Add(@{
            App         = $spName
            Scopes      = ($matched -join ', ')
            ConsentType = $grant.consentType
            Scope       = if ($grant.consentType -eq 'AllPrincipals') { 'Tenant-wide (ALL users)' } else { 'Per-user' }
        }) | Out-Null
    }

    if ($riskyGrants.Count -gt 0) {
        $tenantWide = @($riskyGrants | Where-Object { $_.ConsentType -eq 'AllPrincipals' })
        $riskLevel  = if ($tenantWide.Count -gt 0) { 'High' } else { 'Medium' }

        Add-Finding -Category 'Applications' -RuleId 'AZ-OAuthConsent' `
            -Title "$($riskyGrants.Count) app(s) have delegated consent to sensitive Graph scopes ($($tenantWide.Count) tenant-wide)" `
            -Risk $riskLevel `
            -Detail "These apps were granted delegated permissions (user or admin consent) to sensitive APIs like Mail.Read, Files.ReadWrite.All, or Directory.Read.All. Tenant-wide (AllPrincipals) grants affect every user. This is the primary vector for OAuth consent phishing — attacker registers a malicious app, tricks a user/admin into consenting, and gets persistent access without credentials." `
            -Remediation '1. Review all grants in Entra ID > Enterprise Apps > Permissions. 2. Revoke consent for apps no longer used. 3. Enable Admin Consent Workflow — users request, admins approve. 4. Set App Consent Policy to block user consent for high-privilege permissions. 5. Use Defender for Cloud Apps to monitor OAuth grant activity.' `
            -Data ($riskyGrants | Select-Object -First 25)
    } else {
        Write-OK "OAuth2 consents: no high-risk delegated grants found"
    }
}

#endregion

#region ── CHECK: Registered Devices ──────────────────────────────────────────

function Invoke-CheckDevices {
    Write-Status "Checking registered device health and compliance..."

    $devices = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/devices?`$select=id,displayName,accountEnabled,approximateLastSignInDateTime,isCompliant,isManaged,operatingSystem,operatingSystemVersion,trustType&`$top=999"

    $now            = Get-Date
    $staleDevices   = [System.Collections.Generic.List[hashtable]]::new()
    $nonCompliant   = [System.Collections.Generic.List[hashtable]]::new()
    $enabledCount   = 0

    foreach ($d in $devices) {
        if (-not $d.accountEnabled) { continue }
        $enabledCount++

        $lastSeenStr = 'Unknown'
        $daysSince   = $null
        if ($d.approximateLastSignInDateTime) {
            $lastSeen    = [datetime]$d.approximateLastSignInDateTime
            $daysSince   = [int]($now - $lastSeen).TotalDays
            $lastSeenStr = $lastSeen.ToString('yyyy-MM-dd')
        }

        if ($daysSince -and $daysSince -gt 90) {
            $staleDevices.Add(@{
                Name     = "$($d.displayName)"
                OS       = "$($d.operatingSystem) $($d.operatingSystemVersion)"
                JoinType = "$($d.trustType)"
                LastSeen = $lastSeenStr
                DaysAgo  = $daysSince
            }) | Out-Null
        }

        if ($d.isCompliant -eq $false -and $d.isManaged -eq $true) {
            $nonCompliant.Add(@{
                Name      = "$($d.displayName)"
                OS        = "$($d.operatingSystem)"
                JoinType  = "$($d.trustType)"
                LastSeen  = $lastSeenStr
                Compliant = 'No'
            }) | Out-Null
        }
    }

    $Script:TenantData['TotalDevices'] = $devices.Count
    $Script:TenantData['StaleDevices'] = $staleDevices.Count
    Write-OK "Devices: $($devices.Count) total, $($staleDevices.Count) stale (>90 days inactive)"

    if ($staleDevices.Count -gt 0) {
        Add-Finding -Category 'Devices' -RuleId 'AZ-StaleDevice' `
            -Title "$($staleDevices.Count) registered device(s) not seen for over 90 days" `
            -Risk 'Low' `
            -Detail "Stale devices in the directory may belong to departed employees, decommissioned machines, or abandoned workstations. They persist as valid Azure AD objects and may affect Conditional Access token evaluations or be re-enrolled fraudulently." `
            -Remediation '1. Enable auto-delete for stale devices: Entra ID > Devices > Device Settings > set cleanup rule to 90 days. 2. Use Intune Device Cleanup Rules. 3. Review and delete devices manually for departed employees. 4. Ensure device enrollment is tied to active user lifecycle.' `
            -Data ($staleDevices | Sort-Object DaysAgo -Descending | Select-Object -First 30)
    }

    if ($nonCompliant.Count -gt 0) {
        Add-Finding -Category 'Devices' -RuleId 'AZ-NonCompliantDevice' `
            -Title "$($nonCompliant.Count) Intune-managed device(s) are not compliant with policy" `
            -Risk 'Medium' `
            -Detail "Non-compliant devices lack required security controls (BitLocker, antivirus, OS patch level, etc.). If Conditional Access requires device compliance, these users may be blocked. If it does not, non-compliant devices have unrestricted access to corporate resources." `
            -Remediation '1. Review Intune compliance policies — ensure BitLocker, antivirus, and minimum OS version are set. 2. Create or strengthen CA policy: Require compliant device for all cloud apps. 3. Work with device owners to fix non-compliance. 4. Set grace period for remediation.' `
            -Data ($nonCompliant | Select-Object -First 25)
    }
}

#endregion

#region ── CHECK: SSPR and Weak Reset Methods ─────────────────────────────────

function Invoke-CheckSSPR {
    Write-Status "Checking Self-Service Password Reset and weak authentication methods..."

    $authMethodPolicy = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    if (-not $authMethodPolicy) {
        Write-Warn "Could not retrieve auth methods policy"
        return
    }

    $weakSsprMethods = @('sms','voice','email')
    $enabledWeak = @()

    foreach ($m in $authMethodPolicy.authenticationMethodConfigurations) {
        if ($m.id -in $weakSsprMethods -and $m.state -eq 'enabled') {
            $enabledWeak += $m.id
        }
    }

    if ($enabledWeak.Count -gt 0) {
        Add-Finding -Category 'AuthMethods' -RuleId 'AZ-SSPRWeakMethod' `
            -Title "SSPR / MFA allows weak methods that are vulnerable to SIM-swap: $($enabledWeak -join ', ')" `
            -Risk 'Medium' `
            -Detail "SMS OTP, voice call, and alternate email are vulnerable to SIM-swapping, SS7 protocol attacks, and email account compromise. An attacker who controls a victim's phone number can use SSPR to reset their Azure AD password — gaining access to all their apps without knowing the original password." `
            -Remediation '1. Disable SMS and voice call in Authentication Methods policy. 2. Enable Microsoft Authenticator (push notification) and FIDO2 keys as primary methods. 3. Configure SSPR to require two strong methods. 4. For high-value accounts, restrict SSPR or require helpdesk intervention.' `
            -Data @($enabledWeak | ForEach-Object { @{ Method = $_; Risk = 'SIM-swap/Email compromise' } })
    } else {
        Write-OK "SSPR: no weak reset methods (SMS/voice) detected as enabled"
    }
}

#endregion

#region ── CHECK: Admin Account Security (Synced Admins) ─────────────────────

function Invoke-CheckAdminAccounts {
    Write-Status "Checking admin account security (cloud-only vs synced)..."

    if (-not $Script:AllPrivMembers -or $Script:AllPrivMembers.Count -eq 0) {
        Write-OK "No privileged members to analyze"
        return
    }

    $syncedAdmins = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($member in $Script:AllPrivMembers) {
        if ($member.Risk -notin @('Critical','High')) { continue }
        $upn = $member.UPN
        if (-not $upn -or $upn -notmatch '@') { continue }

        $u = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/users/${upn}?`$select=id,displayName,userPrincipalName,onPremisesSyncEnabled"
        if ($u -and $u.onPremisesSyncEnabled -eq $true) {
            $syncedAdmins.Add(@{
                Name     = "$($member.User)"
                UPN      = $upn
                Role     = "$($member.Role)"
                RoleRisk = "$($member.Risk)"
                Note     = 'On-prem compromise => cloud admin compromise'
            }) | Out-Null
        }
    }

    if ($syncedAdmins.Count -gt 0) {
        Add-Finding -Category 'Roles' -RuleId 'AZ-SyncedAdmin' `
            -Title "$($syncedAdmins.Count) privileged admin(s) use on-premises synced accounts (cloud/on-prem boundary broken)" `
            -Risk 'High' `
            -Detail "Admin accounts synced from on-premises Active Directory collapse the cloud/on-prem security boundary. If on-prem AD is compromised (Golden Ticket, DCSync, Pass-the-Hash), the attacker automatically inherits Azure AD admin privileges. Microsoft's secure administration guidance explicitly prohibits syncing privileged accounts to the cloud." `
            -Remediation '1. Create dedicated cloud-only accounts (e.g. admin_jsmith@tenant.onmicrosoft.com) for all Critical/High roles. 2. Remove privileged roles from synced accounts. 3. Never use .onmicrosoft.com UPN routing for synced accounts assigned to admin roles. 4. Enable PIM + MFA for all cloud admin activations.' `
            -Data $syncedAdmins
    } else {
        Write-OK "Admin accounts: all privileged accounts are cloud-only (good)"
    }
}

#endregion

#region ── CHECK: Sign-In Frequency & Persistent Sessions ───────────────────

function Invoke-CheckSignInFrequency {
    Write-Status "Checking Conditional Access session controls (sign-in frequency)..."

    $caPolicies = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$select=id,displayName,state,sessionControls,conditions"
    $enabled    = @($caPolicies | Where-Object { $_.state -eq 'enabled' })

    $hasFreqPolicy        = $false
    $hasPersistentBlock   = $false

    foreach ($p in $enabled) {
        $sc = $p.sessionControls
        if ($sc -and $sc.signInFrequency -and $sc.signInFrequency.isEnabled -eq $true) {
            $hasFreqPolicy = $true
        }
        if ($sc -and $sc.persistentBrowser -and $sc.persistentBrowser.isEnabled -eq $true -and
            $sc.persistentBrowser.mode -eq 'never') {
            $hasPersistentBlock = $true
        }
    }

    if (-not $hasFreqPolicy) {
        Add-Finding -Category 'ConditionalAccess' -RuleId 'AZ-NoSignInFrequency' `
            -Title 'No Conditional Access policy enforces sign-in frequency (session re-authentication)' `
            -Risk 'Medium' `
            -Detail "Without sign-in frequency controls, refresh tokens are valid indefinitely (or up to 90 days by default). A stolen refresh token gives persistent access with no forced re-authentication. Attackers who steal tokens via AiTM phishing, malware, or OAuth consent maintain access until the token is explicitly revoked." `
            -Remediation "Create a CA policy with session controls: Session Controls > Sign-in frequency > set to 1-8 hours for privileged users, 24 hours for regular users. Additionally enable Continuous Access Evaluation (CAE) for near-real-time token revocation on user risk events."
    }

    if (-not $hasPersistentBlock) {
        Add-Finding -Category 'ConditionalAccess' -RuleId 'AZ-PersistentBrowser' `
            -Title 'No CA policy blocks persistent browser sessions (Stay signed in)' `
            -Risk 'Low' `
            -Detail "Persistent browser sessions (the Stay signed in? prompt) allow long-lived session cookies on shared or unmanaged devices. On a compromised or shared device, these sessions persist beyond the user closing the browser." `
            -Remediation "Add session control to relevant CA policies: Session Controls > Persistent browser session > Never persistent. Apply at minimum to policies covering unmanaged/non-compliant devices."
    }

    Write-OK "Sign-in frequency: check complete (freq=$hasFreqPolicy, persistentBlock=$hasPersistentBlock)"
}

#endregion

#region ── CHECK: Service Principal Certificate Expiry ───────────────────────

function Invoke-CheckSPCertificates {
    Write-Status "Checking service principal certificate credentials for expiry..."

    $now = Get-Date
    $sps = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,displayName,keyCredentials&`$top=999"

    $expiredCerts  = [System.Collections.Generic.List[hashtable]]::new()
    $expiringCerts = [System.Collections.Generic.List[hashtable]]::new()
    $noExpiryCerts = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($sp in $sps) {
        if (-not $sp.keyCredentials -or $sp.keyCredentials.Count -eq 0) { continue }
        foreach ($cert in $sp.keyCredentials) {
            if (-not $cert.endDateTime) { continue }
            try {
                $expiry     = [datetime]$cert.endDateTime
                $daysLeft   = [int]($expiry - $now).TotalDays
                $expiryStr  = $expiry.ToString('yyyy-MM-dd')

                if ($expiry -lt $now) {
                    $expiredCerts.Add(@{ App=$sp.displayName; Expiry=$expiryStr; DaysAgo=[Math]::Abs($daysLeft) }) | Out-Null
                } elseif ($daysLeft -lt 30) {
                    $expiringCerts.Add(@{ App=$sp.displayName; Expiry=$expiryStr; DaysLeft=$daysLeft }) | Out-Null
                } elseif ($cert.endDateTime -match '2299|9999') {
                    $noExpiryCerts.Add(@{ App=$sp.displayName; Expiry=$expiryStr }) | Out-Null
                }
            } catch {}
        }
    }

    if ($expiredCerts.Count -gt 0) {
        Add-Finding -Category 'Applications' -RuleId 'AZ-SPExpiredCert' `
            -Title "$($expiredCerts.Count) service principal(s) have EXPIRED certificate credentials" `
            -Risk 'Medium' `
            -Detail "Expired certificate credentials on service principals cause authentication failures for dependent applications. While expired certs cannot be actively used for auth, their presence indicates the certificate lifecycle is not being managed — the same oversight likely affects other certs and secrets that ARE still valid." `
            -Remediation "Rotate expired certificates immediately. Implement certificate lifecycle alerts in Entra ID (Monitor > Diagnostic settings) or via a custom script to alert 60/30/7 days before expiry. Consider Managed Identities which eliminate certificate management entirely." `
            -Data ($expiredCerts | Select-Object -First 20)
    }

    if ($expiringCerts.Count -gt 0) {
        Add-Finding -Category 'Applications' -RuleId 'AZ-SPExpiringCert' `
            -Title "$($expiringCerts.Count) service principal(s) have certificates expiring within 30 days" `
            -Risk 'Medium' `
            -Detail "Certificate credentials expiring within 30 days will soon cause authentication failures if not rotated. Application outages from expired certs are a common and avoidable incident." `
            -Remediation "Rotate expiring certificates before expiry date. Establish an alerting process for certificate expiry at 60, 30, and 7 days. Use Azure Key Vault with auto-rotation policies." `
            -Data ($expiringCerts | Select-Object -First 20)
    }

    Write-OK "SP Certificates: $($expiredCerts.Count) expired, $($expiringCerts.Count) expiring soon"
}

#endregion

#region ── CHECK: M365 Group and App Registration Creation Policy ─────────────

function Invoke-CheckGroupSettings {
    Write-Status "Checking who can create Microsoft 365 Groups and app registrations..."

    # Group creation policy via directory settings
    $settings = Get-GraphAll -Uri "https://graph.microsoft.com/v1.0/groupSettings"
    $groupPolicy = $settings | Where-Object { $_.templateId -match '62375ab9|08d542b9' }

    if ($groupPolicy) {
        $enableGroupCreation = ($groupPolicy.values | Where-Object { $_.name -eq 'EnableGroupCreation' }).value
        $groupCreatorsGroup  = ($groupPolicy.values | Where-Object { $_.name -eq 'GroupCreationAllowedGroupId' }).value

        if ($enableGroupCreation -eq 'true' -and -not $groupCreatorsGroup) {
            Add-Finding -Category 'GuestSettings' -RuleId 'AZ-OpenGroupCreation' `
                -Title 'Any user can create Microsoft 365 Groups (no creation restriction configured)' `
                -Risk 'Low' `
                -Detail "When any user can create M365 Groups, they also create associated Teams, SharePoint sites, Planner boards, and shared mailboxes. This leads to uncontrolled data sprawl, external sharing exposure (if each Group owner can invite guests), and increased attack surface from abandoned resources." `
                -Remediation "Restrict group creation: (1) Set EnableGroupCreation = false in directory settings. (2) Create a designated group (e.g. 'Group Creators') and set GroupCreationAllowedGroupId. (3) Implement an approval workflow via Microsoft Forms or Power Automate for group requests."
        }
    }

    # App registration policy (can all users create app registrations?)
    $authPolicy = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    if ($authPolicy -and $authPolicy.defaultUserRolePermissions) {
        if ($authPolicy.defaultUserRolePermissions.allowedToCreateApps -eq $true) {
            Add-Finding -Category 'Applications' -RuleId 'AZ-UserCreateApps' `
                -Title 'Any user can register Azure AD application registrations' `
                -Risk 'Medium' `
                -Detail "Users who can create app registrations can request OAuth permissions, potentially tricking other users into granting consent to malicious apps (consent phishing). They can also create apps that obtain tokens for Microsoft Graph and use those for data exfiltration." `
                -Remediation "Disable in Entra ID > User Settings: set 'Users can register applications' = No. Implement an admin consent workflow so legitimate app registration requests go through IT review."
        }
    }

    Write-OK "Group settings check complete"
}

#endregion

#region ── CHECK: Cross-Tenant Access Policy (Inbound B2B Trust) ─────────────

function Invoke-CheckCrossTenantAccess {
    Write-Status "Checking cross-tenant access (B2B inbound) settings..."

    $ctap = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default"
    if (-not $ctap) {
        Write-OK "Cross-tenant access policy: not configured (or insufficient permissions)"
        return
    }

    $inbound = $ctap.inboundTrust

    # Check if MFA claims from external tenants are trusted
    if ($inbound -and $inbound.isMfaAccepted -eq $true) {
        Add-Finding -Category 'TenantConfig' -RuleId 'AZ-CrossTenantInbound' `
            -Title 'Cross-tenant access policy trusts MFA claims from all external tenants' `
            -Risk 'Medium' `
            -Detail "Trusting MFA from external tenants means a user who completed MFA in their home tenant is considered MFA-satisfied in your tenant — even if their home tenant has weaker MFA requirements (e.g. SMS only). This can allow external users to bypass your MFA strength requirements." `
            -Remediation "Review cross-tenant access settings: Entra ID > External Identities > Cross-tenant access settings. Either remove MFA trust from the default policy or configure per-tenant settings that only trust MFA from specific, hardened partner tenants."
    }

    # Check if compliant device claims from external tenants are trusted
    if ($inbound -and $inbound.isCompliantDeviceAccepted -eq $true) {
        Add-Finding -Category 'TenantConfig' -RuleId 'AZ-CrossTenantDeviceTrust' `
            -Title 'Cross-tenant access policy trusts device compliance claims from all external tenants' `
            -Risk 'Medium' `
            -Detail "Trusting device compliance from external tenants means you rely on their Intune policies and compliance baselines — which may be weaker than yours. An external tenant with permissive compliance policies could allow non-compliant devices to access your resources." `
            -Remediation "Remove or scope device compliance trust in cross-tenant access settings. Only trust device compliance from specific partner tenants after verifying their Intune policies meet your standards."
    }

    Write-OK "Cross-tenant access policy checked"
}

#endregion

#region ── CHECK: Break-Glass Account Validation ─────────────────────────────

function Invoke-CheckBreakGlassAccounts {
    Write-Status "Validating break-glass (emergency access) account configuration..."

    # Criteria for a proper break-glass account:
    # 1. Cloud-only (not synced from on-prem)
    # 2. Global Administrator role
    # 3. Not included in any blocking CA policy (or excluded from all MFA policies)
    # 4. Should ideally use .onmicrosoft.com UPN

    $gasCloudOnly  = [System.Collections.Generic.List[hashtable]]::new()
    $gasSynced     = [System.Collections.Generic.List[string]]::new()

    foreach ($upn in $Script:GlobalAdmins) {
        $u = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/users/${upn}?`$select=id,displayName,userPrincipalName,onPremisesSyncEnabled,accountEnabled"
        if (-not $u) { continue }
        if ($u.onPremisesSyncEnabled -eq $true) {
            $gasSynced.Add($upn) | Out-Null
        } elseif ($u.accountEnabled -eq $true) {
            $gasCloudOnly.Add(@{
                UPN           = $upn
                Name          = $u.displayName
                IsOnMSFTDomain= ($upn -match '\.onmicrosoft\.com$')
            }) | Out-Null
        }
    }

    # If ALL GAs are synced, there is no cloud-only break-glass
    if ($gasCloudOnly.Count -eq 0 -and $Script:GlobalAdmins.Count -gt 0) {
        Add-Finding -Category 'Roles' -RuleId 'AZ-NoBreakGlass' `
            -Title 'No cloud-only Global Administrator account found — break-glass access may not be available' `
            -Risk 'High' `
            -Detail "All Global Administrator accounts appear to be synced from on-premises Active Directory. If Azure AD Connect, AD FS, or on-prem AD becomes unavailable, there is no cloud-native emergency access path. Microsoft strongly recommends at least 2 cloud-only (not synced) GA accounts as break-glass accounts for disaster recovery." `
            -Remediation "1. Create 2 dedicated cloud-only GA accounts with .onmicrosoft.com UPNs (e.g. bg01@tenant.onmicrosoft.com). 2. Use 128+ character random passwords stored in a physical safe. 3. Exclude them from all CA policies. 4. Enable alerting on any sign-in from these accounts. 5. Test access quarterly." `
            -Data @($Script:GlobalAdmins | ForEach-Object { @{ UPN=$_; Source='Synced' } })
    } elseif ($gasCloudOnly.Count -lt 2) {
        Add-Finding -Category 'Roles' -RuleId 'AZ-InsufficientBreakGlass' `
            -Title "Only $($gasCloudOnly.Count) cloud-only GA account(s) found — Microsoft recommends at least 2 break-glass accounts" `
            -Risk 'Medium' `
            -Detail "Microsoft recommends a minimum of 2 cloud-only GA accounts for emergency access. With only 1, a single account compromise or lockout eliminates emergency recovery capability." `
            -Remediation "Create a second cloud-only GA account for break-glass. Store credentials securely offline. Exclude both from all CA policies. Set up sign-in monitoring alerts." `
            -Data $gasCloudOnly
    } else {
        # Check if any cloud-only GA uses .onmicrosoft.com (recommended)
        $noMsDomain = @($gasCloudOnly | Where-Object { -not $_.IsOnMSFTDomain })
        if ($noMsDomain.Count -gt 0) {
            Add-Finding -Category 'Roles' -RuleId 'AZ-BreakGlassDomain' `
                -Title "$($noMsDomain.Count) cloud-only GA account(s) do not use the .onmicrosoft.com domain (break-glass best practice)" `
                -Risk 'Low' `
                -Detail "Break-glass accounts should use the tenant's initial .onmicrosoft.com domain. Custom domain authentication depends on DNS and federation infrastructure that may be unavailable in a disaster scenario. The .onmicrosoft.com domain is always available regardless of DNS or AD FS state." `
                -Remediation "Ensure break-glass accounts use UPNs in the format user@tenant.onmicrosoft.com. This guarantees login availability even if custom domain DNS is disrupted." `
                -Data $noMsDomain
        } else {
            Write-OK "Break-glass: $($gasCloudOnly.Count) cloud-only GA accounts with .onmicrosoft.com domain found"
        }
    }
}

#endregion

#region ── HTML Report ─────────────────────────────────────────────────────────

function Get-RiskColor { param([string]$r)
    switch($r){'Critical'{'#dc3545'}'High'{'#fd7e14'}'Medium'{'#e6a817'}'Low'{'#20c997'}default{'#6c757d'}}
}
function Get-RiskOrder { param([string]$r)
    switch($r){'Critical'{0}'High'{1}'Medium'{2}'Low'{3}default{4}}
}
function Get-RiskScore {
    $s=100
    foreach($f in $Script:Findings){switch($f.Risk){'Critical'{$s-=25}'High'{$s-=10}'Medium'{$s-=5}'Low'{$s-=2}}}
    return [Math]::Max(0,$s)
}

function Build-DataTable {
    param([object[]]$Items,[int]$Max=50)
    if(-not $Items -or $Items.Count -eq 0){return ''}
    $sample  = $Items[0]
    $limited = $Items | Select-Object -First $Max
    $total   = $Items.Count
    if($sample -is [hashtable]){
        $cols = @($sample.Keys) | Select-Object -First 6
        $hdr  = ($cols | ForEach-Object {"<th>$(HE $_)</th>"}) -join ''
        $rows = ($limited | ForEach-Object {
            $row=$_; $cells=($cols | ForEach-Object {
                $v = if($row.ContainsKey($_)){"$($row[$_])"}else{''}
                "<td>$(HE $v)</td>"
            }) -join ''; "<tr>$cells</tr>"
        }) -join ''
        $more = if($total -gt $Max){"<tr class='more-row'><td colspan='$($cols.Count)'>... and $($total-$Max) more</td></tr>"}else{''}
        return "<div class='data-tbl-wrap'><table class='data-tbl'><thead><tr>$hdr</tr></thead><tbody>$rows$more</tbody></table></div>"
    } else {
        $rows = ($limited | ForEach-Object {"<tr><td>$(HE "$_")</td></tr>"}) -join ''
        $more = if($total -gt $Max){"<tr class='more-row'><td>... and $($total-$Max) more</td></tr>"}else{''}
        return "<div class='data-tbl-wrap'><table class='data-tbl'><tbody>$rows$more</tbody></table></div>"
    }
}

function Build-FindingRows {
    $sb  = [System.Text.StringBuilder]::new()
    $idx = 0
    $all = $Script:Findings | Sort-Object { Get-RiskOrder $_.Risk }, Category
    foreach($f in $all){
        $idx++
        $color   = Get-RiskColor $f.Risk
        $ttp     = if($Script:MitreTTPMap.ContainsKey($f.RuleId)){$Script:MitreTTPMap[$f.RuleId]}else{''}
        $ttpLink = if($ttp){"<a class='ttp-link' href='https://attack.mitre.org/techniques/$($ttp.Replace(".","/"))/' target='_blank'>$ttp</a>"}else{'<span class="ttp-none">—</span>'}
        $dataItems = if($f.Data){@($f.Data)}else{@()}
        $hasData   = $dataItems.Count -gt 0
        $dataHtml  = if($hasData){Build-DataTable -Items $dataItems}else{''}
        $dataBadge = if($hasData){"<span class='data-count'>$($dataItems.Count) affected</span>"}else{''}
        $remedHtml = '<ol class="remed-list">'
        $f.Remediation -split '(?<=[.;])\s+(?=[0-9]\)|[A-Z])' | ForEach-Object { if($_.Trim()){$remedHtml += "<li>$(HE $_.Trim())</li>"} }
        $remedHtml += '</ol>'
        [void]$sb.Append(@"
<div class="finding-card" data-risk="$($f.Risk.ToLower())" data-category="$(HE $f.Category)" data-id="f$idx">
  <div class="finding-hdr" onclick="toggleFinding(this)">
    <span class="chevron">&#9656;</span>
    <span class="risk-pill" style="background:$color">$($f.Risk)</span>
    <span class="rule-id">$($f.RuleId)</span>
    <span class="finding-title">$(HE $f.Title)</span>
    <span class="finding-meta">
      <span class="cat-tag">$($f.Category)</span>
      $dataBadge
      $ttpLink
    </span>
  </div>
  <div class="finding-body" id="fb$idx" style="display:none">
    <div class="finding-desc">$(HE $f.Detail)</div>
    $(if($hasData){"<div class='affected-wrap'><div class='affected-lbl'>Affected Objects ($($dataItems.Count))</div>$dataHtml</div>"})
    <div class="remed-wrap"><div class="remed-lbl">Remediation Steps</div>$remedHtml</div>
  </div>
</div>
"@)
    }
    return $sb.ToString()
}

function New-HTMLReport { param([string]$Out)
    $score = Get-RiskScore
    $sc    = if($score -ge 80){'#28a745'}elseif($score -ge 60){'#ffc107'}elseif($score -ge 40){'#fd7e14'}else{'#dc3545'}
    $crit  = ($Script:Findings|Where-Object Risk -eq 'Critical').Count
    $high  = ($Script:Findings|Where-Object Risk -eq 'High').Count
    $med   = ($Script:Findings|Where-Object Risk -eq 'Medium').Count
    $low   = ($Script:Findings|Where-Object Risk -eq 'Low').Count
    $info  = ($Script:Findings|Where-Object Risk -eq 'Info').Count
    $t     = $Script:TenantData
    $circ  = 339.3
    $filled= [Math]::Round($circ * $score / 100, 1)
    $gap   = $circ - $filled
    $elapsed = [Math]::Round((New-TimeSpan -Start $StartTime -End (Get-Date)).TotalSeconds)

    $findingRowsHtml = Build-FindingRows
    $userInventoryHtml = Build-DataTable -Items $Script:UserInventory -Max 300
    $failedHtml = ''
    if($Script:FailedModules.Count -gt 0){
        $frows = ($Script:FailedModules | ForEach-Object {"<tr><td><code>$($_.Name)</code></td><td style='color:#dc3545'>$(HE $_.Error)</td><td>$($_.Line)</td></tr>"}) -join ''
        $failedHtml = "<div class='section'><h2 class='section-h warn-h'>&#9888; Modules With Errors ($($Script:FailedModules.Count))</h2><p class='note'>These modules errored — findings may be incomplete.</p><table class='info-tbl'><thead><tr><th>Module</th><th>Error</th><th>Line</th></tr></thead><tbody>$frows</tbody></table></div>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AzureAD-Recon — $($t['Name'])</title>
<style>
:root{
  --c:#dc3545;--h:#fd7e14;--m:#e6a817;--l:#20c997;--i:#6c757d;
  --bg:#f0f4fb;--card:#fff;--border:#dde2ee;--text:#1a1d23;--sub:#5a6375;
  --hdr1:#0050a0;--hdr2:#0078d4;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,Arial,sans-serif;background:var(--bg);color:var(--text);font-size:14px}
a{color:#0078d4;text-decoration:none}a:hover{text-decoration:underline}
.hdr{background:linear-gradient(135deg,var(--hdr1),var(--hdr2));color:#fff;padding:28px 40px 24px;display:flex;align-items:center;gap:36px;flex-wrap:wrap}
.hdr-text h1{font-size:1.7rem;font-weight:800;letter-spacing:-.3px}
.hdr-text p{opacity:.75;margin-top:6px;font-size:.88rem}
.hdr-meta{display:flex;gap:20px;margin-top:10px;flex-wrap:wrap}
.hdr-meta span{font-size:.8rem;opacity:.8}.hdr-meta b{opacity:1}
.score-ring{flex-shrink:0;text-align:center}
.stats-bar{background:#fff;border-bottom:1px solid var(--border);padding:0 40px;display:flex;flex-wrap:wrap}
.stat-item{padding:16px 20px;display:flex;flex-direction:column;align-items:center;border-right:1px solid var(--border);cursor:pointer;transition:background .15s;min-width:90px}
.stat-item:hover{background:#f0f4fb}
.stat-num{font-size:1.5rem;font-weight:800;line-height:1}
.stat-lbl{font-size:.7rem;color:var(--sub);margin-top:3px;text-transform:uppercase;letter-spacing:.4px}
.sc{color:var(--c)}.sh{color:var(--h)}.sm{color:var(--m)}.sl{color:var(--l)}.si{color:var(--i)}.saz{color:#0078d4}
.toolbar{background:#fff;border-bottom:1px solid var(--border);padding:10px 40px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;position:sticky;top:0;z-index:50;box-shadow:0 2px 8px rgba(0,0,0,.06)}
.search-box{flex:1;min-width:200px;max-width:380px;position:relative}
.search-box input{width:100%;padding:7px 12px 7px 34px;border:1px solid var(--border);border-radius:6px;font-size:.87rem;outline:none}
.search-box input:focus{border-color:#0078d4;box-shadow:0 0 0 3px rgba(0,120,212,.12)}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--sub)}
.filter-btns{display:flex;gap:6px;flex-wrap:wrap}
.fbtn{padding:5px 14px;border-radius:20px;border:1.5px solid var(--border);background:#fff;font-size:.78rem;font-weight:600;cursor:pointer;transition:all .15s}
.fbtn:hover{border-color:#0078d4;color:#0078d4}
.fbtn.active{color:#fff;border-color:currentColor}
.fbtn-all.active{background:#0078d4;border-color:#0078d4}
.fbtn-critical.active{background:var(--c);border-color:var(--c)}
.fbtn-high.active{background:var(--h);border-color:var(--h)}
.fbtn-medium.active{background:var(--m);border-color:var(--m)}
.fbtn-low.active{background:var(--l);border-color:var(--l)}
.fbtn-info.active{background:var(--i);border-color:var(--i)}
.toolbar-right{margin-left:auto;display:flex;gap:8px}
.btn{padding:6px 14px;border-radius:6px;border:1.5px solid var(--border);background:#fff;font-size:.8rem;cursor:pointer;font-weight:600;transition:all .15s;display:flex;align-items:center;gap:5px}
.btn:hover{border-color:#0078d4;color:#0078d4}
.btn-primary{background:#0078d4;border-color:#0078d4;color:#fff}
.btn-primary:hover{background:#006ac1}
.container{max-width:1400px;margin:0 auto;padding:24px 40px}
.section{background:var(--card);border:1px solid var(--border);border-radius:10px;margin-bottom:20px;overflow:hidden}
.section-h{font-size:1rem;font-weight:700;padding:14px 20px;border-bottom:1px solid var(--border);background:#f8f9fc;display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none}
.section-h .toggle-icon{margin-left:auto;color:var(--sub);font-size:.8rem}
.warn-h{background:#fff8f0;color:#b35c00;border-bottom-color:#fde5c8}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:0}
.info-col{padding:16px 20px}.info-col:first-child{border-right:1px solid var(--border)}
.info-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px dashed var(--border);font-size:.87rem}
.info-row:last-child{border-bottom:none}
.info-key{color:var(--sub)}.info-val{font-weight:600;text-align:right}
.info-val.bad{color:var(--c)}.info-val.warn{color:var(--h)}.info-val.ok{color:#28a745}
.info-tbl{width:100%;border-collapse:collapse;font-size:.87rem}
.info-tbl th{background:#f8f9fc;padding:9px 14px;text-align:left;font-weight:600;border-bottom:2px solid var(--border);font-size:.8rem;text-transform:uppercase;letter-spacing:.3px;color:var(--sub)}
.info-tbl td{padding:9px 14px;border-bottom:1px solid #f0f2f8}
.info-tbl tr:last-child td{border-bottom:none}.info-tbl tr:hover td{background:#f8f9fc}
.note{padding:10px 20px;font-size:.85rem;color:var(--sub)}
.no-data{padding:20px;color:var(--sub);font-style:italic;text-align:center}
.pill{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.72rem;font-weight:700}
.pill.ok{background:#d4edda;color:#155724}.pill.bad{background:#f8d7da;color:#721c24}.pill.warn{background:#fff3cd;color:#856404}
.findings-toolbar{padding:12px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;background:#f8f9fc}
.findings-count{font-size:.82rem;color:var(--sub)}
.findings-list{padding:0}
.finding-card{border-bottom:1px solid var(--border)}
.finding-card:last-child{border-bottom:none}
.finding-card[data-risk="critical"] .finding-hdr{border-left:4px solid var(--c)}
.finding-card[data-risk="high"]     .finding-hdr{border-left:4px solid var(--h)}
.finding-card[data-risk="medium"]   .finding-hdr{border-left:4px solid var(--m)}
.finding-card[data-risk="low"]      .finding-hdr{border-left:4px solid var(--l)}
.finding-card[data-risk="info"]     .finding-hdr{border-left:4px solid var(--i)}
.finding-hdr{display:flex;align-items:center;gap:10px;padding:12px 20px;cursor:pointer;transition:background .12s;flex-wrap:wrap}
.finding-hdr:hover{background:#f0f4fb}
.chevron{color:var(--sub);font-size:.75rem;transition:transform .18s;flex-shrink:0}
.chevron.open{transform:rotate(90deg)}
.risk-pill{display:inline-block;padding:3px 11px;border-radius:20px;font-size:.72rem;font-weight:700;color:#fff;white-space:nowrap;flex-shrink:0}
.rule-id{font-family:'Cascadia Code','Consolas',monospace;font-size:.78rem;color:var(--sub);background:#f0f2f8;padding:2px 8px;border-radius:4px;white-space:nowrap;flex-shrink:0}
.finding-title{font-weight:600;font-size:.92rem;flex:1;min-width:200px}
.finding-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-left:auto;flex-shrink:0}
.cat-tag{padding:2px 9px;border-radius:10px;background:#e5f0fb;color:#004578;font-size:.72rem;font-weight:600}
.data-count{padding:2px 9px;border-radius:10px;background:#fff3cd;color:#856404;font-size:.72rem;font-weight:700;white-space:nowrap}
.ttp-link{padding:2px 8px;border-radius:4px;background:#cce5ff;color:#004085;font-size:.72rem;font-weight:700;border:1px solid #b8daff;white-space:nowrap}
.ttp-none{color:#bbb;font-size:.8rem}
.finding-body{padding:0 20px 18px 52px;background:#f8fbff}
.finding-desc{color:#3a4050;font-size:.87rem;line-height:1.65;margin-bottom:14px;padding-top:12px;border-top:1px dashed var(--border)}
.affected-wrap{margin-bottom:14px}
.affected-lbl{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--sub);margin-bottom:6px}
.data-tbl-wrap{overflow-x:auto;border-radius:6px;border:1px solid var(--border)}
.data-tbl{width:100%;border-collapse:collapse;font-size:.82rem}
.data-tbl th{background:#e8f0fa;padding:7px 12px;text-align:left;font-weight:600;color:var(--sub);border-bottom:1px solid var(--border);font-size:.75rem;text-transform:uppercase;letter-spacing:.3px}
.data-tbl td{padding:7px 12px;border-bottom:1px solid #f0f2f8;font-family:'Cascadia Code','Consolas',monospace;font-size:.8rem}
.data-tbl tr:last-child td{border-bottom:none}.data-tbl tr:hover td{background:#f0f4fb}
.more-row td{color:var(--sub);font-style:italic;text-align:center;padding:6px;font-family:inherit}
.remed-wrap{background:#f0f7ff;border:1px solid #b8daff;border-radius:6px;padding:12px 16px}
.remed-lbl{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#004085;margin-bottom:8px}
.remed-list{padding-left:18px;color:#003366;font-size:.85rem;line-height:1.7}
.remed-list li{margin-bottom:4px}
.no-results{padding:40px;text-align:center;color:var(--sub);display:none}
.footer{text-align:center;padding:24px;font-size:.8rem;color:var(--sub);border-top:1px solid var(--border);background:#fff;margin-top:8px}
.footer strong{color:var(--text)}
@media(max-width:768px){
  .hdr,.toolbar,.container,.stats-bar{padding-left:16px;padding-right:16px}
  .info-grid{grid-template-columns:1fr}
  .info-col:first-child{border-right:none;border-bottom:1px solid var(--border)}
  .finding-body{padding-left:16px}
}
@media print{.toolbar,.btn{display:none}.finding-body{display:block !important}}
</style>
</head>
<body>

<div class="hdr">
  <div class="score-ring">
    <svg width="100" height="100" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,.15)" stroke-width="10"/>
      <circle cx="60" cy="60" r="54" fill="none" stroke="$sc" stroke-width="10"
              stroke-dasharray="$filled $gap" stroke-linecap="round" transform="rotate(-90 60 60)"/>
      <text x="60" y="56" text-anchor="middle" dominant-baseline="middle"
            font-size="26" font-weight="900" fill="$sc">$score</text>
      <text x="60" y="74" text-anchor="middle" font-size="10" fill="rgba(255,255,255,.55)" letter-spacing="1">/ 100</text>
    </svg>
  </div>
  <div class="hdr-text">
    <h1>&#9729; AzureAD-Recon — $($t['Name'])</h1>
    <p>Entra ID / Azure Active Directory security assessment</p>
    <div class="hdr-meta">
      <span><b>Tenant ID:</b> $($t['TenantId'])</span>
      <span><b>Generated:</b> $(Get-Date -Format 'yyyy-MM-dd HH:mm')</span>
      <span><b>Duration:</b> ${elapsed}s</span>
      <span><b>Auth:</b> $authMode</span>
    </div>
  </div>
</div>

<div class="stats-bar">
  <div class="stat-item" onclick="setFilter('critical')"><span class="stat-num sc">$crit</span><span class="stat-lbl">Critical</span></div>
  <div class="stat-item" onclick="setFilter('high')"><span class="stat-num sh">$high</span><span class="stat-lbl">High</span></div>
  <div class="stat-item" onclick="setFilter('medium')"><span class="stat-num sm">$med</span><span class="stat-lbl">Medium</span></div>
  <div class="stat-item" onclick="setFilter('low')"><span class="stat-num sl">$low</span><span class="stat-lbl">Low</span></div>
  <div class="stat-item" onclick="setFilter('info')"><span class="stat-num si">$info</span><span class="stat-lbl">Info</span></div>
  <div class="stat-item"><span class="stat-num saz">$($t['GuestCount'])</span><span class="stat-lbl">Guests</span></div>
  <div class="stat-item"><span class="stat-num saz">$($t['CACount'])</span><span class="stat-lbl">CA Policies</span></div>
  <div class="stat-item"><span class="stat-num saz">$(($Script:GlobalAdmins).Count)</span><span class="stat-lbl">Global Admins</span></div>
  <div class="stat-item"><span class="stat-num saz">$($t['TotalUsers'])</span><span class="stat-lbl">Users</span></div>
  <div class="stat-item"><span class="stat-num saz">$($t['TotalDevices'])</span><span class="stat-lbl">Devices</span></div>
</div>

<div class="toolbar">
  <div class="search-box">
    <span class="search-icon">&#128269;</span>
    <input type="text" id="searchInput" placeholder="Search findings, users, app names..." oninput="applyFilters()">
  </div>
  <div class="filter-btns">
    <button class="fbtn fbtn-all active" onclick="setFilter('all')">All ($($Script:Findings.Count))</button>
    <button class="fbtn fbtn-critical" onclick="setFilter('critical')">Critical ($crit)</button>
    <button class="fbtn fbtn-high" onclick="setFilter('high')">High ($high)</button>
    <button class="fbtn fbtn-medium" onclick="setFilter('medium')">Medium ($med)</button>
    <button class="fbtn fbtn-low" onclick="setFilter('low')">Low ($low)</button>
    <button class="fbtn fbtn-info" onclick="setFilter('info')">Info ($info)</button>
  </div>
  <div class="toolbar-right">
    <button class="btn" onclick="expandAll()">&#8597; Expand All</button>
    <button class="btn" onclick="collapseAll()">&#8597; Collapse All</button>
    <button class="btn btn-primary" onclick="exportCSV()">&#8677; Export CSV</button>
  </div>
</div>

<div class="container">

<div class="section">
  <h2 class="section-h" onclick="toggleSection(this)">Tenant Information <span class="toggle-icon">&#9660;</span></h2>
  <div class="section-body">
    <div class="info-grid">
      <div class="info-col">
        <div class="info-row"><span class="info-key">Tenant Name</span><span class="info-val">$($t['Name'])</span></div>
        <div class="info-row"><span class="info-key">Tenant ID</span><span class="info-val">$($t['TenantId'])</span></div>
        <div class="info-row"><span class="info-key">Verified Domains</span><span class="info-val">$(($t['Domains'] -join ', '))</span></div>
        <div class="info-row"><span class="info-key">Hybrid Identity Sync</span><span class="info-val">$(if($t['HybridSync']){'Yes'}else{'Cloud-only'})</span></div>
      </div>
      <div class="info-col">
        <div class="info-row"><span class="info-key">Security Defaults</span><span class="info-val $(if($t['SecurityDefaults']){'ok'}else{'bad'})">$(if($t['SecurityDefaults']){'Enabled'}else{'DISABLED'})</span></div>
        <div class="info-row"><span class="info-key">Legacy Auth Blocked</span><span class="info-val $(if($t['LegacyBlocked']){'ok'}else{'bad'})">$(if($t['LegacyBlocked']){'Yes (CA policy)'}else{'NO — exposed'})</span></div>
        <div class="info-row"><span class="info-key">P2 License (PIM / IDP)</span><span class="info-val $(if($t['HasAADP2']){'ok'}else{'warn'})">$(if($t['HasAADP2']){'Yes'}else{'No'})</span></div>
        <div class="info-row"><span class="info-key">Global Administrators</span><span class="info-val $(if(($Script:GlobalAdmins).Count -gt 5){'bad'}else{'ok'})">$(($Script:GlobalAdmins).Count)</span></div>
      </div>
    </div>
  </div>
</div>

<div class="section">
  <h2 class="section-h" onclick="toggleSection(this)">User Inventory ($($Script:UserInventory.Count) members) <span class="toggle-icon">&#9660;</span></h2>
  <div class="section-body">
    <div class="info-grid" style="grid-template-columns:repeat(5,1fr)">
      <div class="info-col" style="border-right:1px solid var(--border)">
        <div class="info-row"><span class="info-key">Total Users</span><span class="info-val">$($t['TotalUsers'])</span></div>
        <div class="info-row"><span class="info-key">Enabled</span><span class="info-val ok">$($t['EnabledUsers'])</span></div>
      </div>
      <div class="info-col" style="border-right:1px solid var(--border)">
        <div class="info-row"><span class="info-key">Disabled</span><span class="info-val warn">$($t['DisabledUsers'])</span></div>
        <div class="info-row"><span class="info-key">Guests</span><span class="info-val">$($t['GuestCount'])</span></div>
      </div>
      <div class="info-col" style="border-right:1px solid var(--border)">
        <div class="info-row"><span class="info-key">Synced (on-prem)</span><span class="info-val">$($t['SyncedUsers'])</span></div>
        <div class="info-row"><span class="info-key">Cloud-only</span><span class="info-val">$($t['CloudUsers'])</span></div>
      </div>
      <div class="info-col" style="border-right:1px solid var(--border)">
        <div class="info-row"><span class="info-key">Devices</span><span class="info-val">$($t['TotalDevices'])</span></div>
        <div class="info-row"><span class="info-key">Stale Devices</span><span class="info-val $(if(($t['StaleDevices']) -gt 0){'warn'}else{'ok'})">$($t['StaleDevices'])</span></div>
      </div>
      <div class="info-col">
        <div class="info-row"><span class="info-key">Global Admins</span><span class="info-val $(if(($Script:GlobalAdmins).Count -gt 5){'bad'}elseif(($Script:GlobalAdmins).Count -eq 0){'bad'}else{'ok'})">$(($Script:GlobalAdmins).Count)</span></div>
        <div class="info-row"><span class="info-key">CA Policies</span><span class="info-val $(if(($t['CACount']) -gt 0){'ok'}else{'bad'})">$($t['CACount'])</span></div>
      </div>
    </div>
    <div style="padding:0 20px 16px">
      <p class="note" style="margin-bottom:8px">Full user list — showing up to 300 members (guests excluded). Columns: Enabled, Source (Cloud/Synced), Last Sign-In, Password Expiry, Licensed, Issues detected.</p>
      $userInventoryHtml
    </div>
  </div>
</div>

<div class="section" id="findings-section">
  <h2 class="section-h" style="cursor:default">Security Findings</h2>
  <div class="findings-toolbar">
    <span class="findings-count" id="results-label">Showing $($Script:Findings.Count) findings — click any row to expand</span>
  </div>
  <div class="findings-list" id="findings-list">
$findingRowsHtml
    <div class="no-results" id="no-results">No findings match the current filter.</div>
  </div>
</div>

$failedHtml

</div>

<div class="footer">
  <strong>AzureAD-Recon by Harsh P</strong> &nbsp;|&nbsp;
  <a href="https://github.com/MrHarshvardhan" target="_blank">github.com/MrHarshvardhan</a> &nbsp;|&nbsp;
  Score: $score/100 &nbsp;|&nbsp;
  $($Script:Findings.Count) findings ($crit Critical, $high High, $med Medium, $low Low) &nbsp;|&nbsp;
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
</div>

<script>
var currentFilter='all',searchTerm='';
function toggleFinding(hdr){
  var body=hdr.nextElementSibling,chevron=hdr.querySelector('.chevron'),open=body.style.display!=='none';
  body.style.display=open?'none':'block';chevron.classList.toggle('open',!open);
}
function expandAll(){
  document.querySelectorAll('.finding-card:not([style*="display:none"]) .finding-hdr').forEach(function(h){
    h.nextElementSibling.style.display='block';h.querySelector('.chevron').classList.add('open');
  });
}
function collapseAll(){
  document.querySelectorAll('.finding-body').forEach(function(b){b.style.display='none';});
  document.querySelectorAll('.chevron').forEach(function(c){c.classList.remove('open');});
}
function toggleSection(hdr){
  var body=hdr.nextElementSibling,icon=hdr.querySelector('.toggle-icon'),open=body.style.display!=='none';
  body.style.display=open?'none':'';icon.innerHTML=open?'&#9650;':'&#9660;';
}
function setFilter(risk){
  currentFilter=risk;
  document.querySelectorAll('.fbtn').forEach(function(b){b.classList.remove('active');});
  var a=document.querySelector('.fbtn-'+risk);if(a)a.classList.add('active');
  applyFilters();
}
function applyFilters(){
  searchTerm=document.getElementById('searchInput').value.toLowerCase();
  var cards=document.querySelectorAll('.finding-card'),visible=0;
  cards.forEach(function(card){
    var rm=(currentFilter==='all'||card.dataset.risk===currentFilter);
    var text=card.querySelector('.finding-hdr').textContent.toLowerCase();
    var fb=card.querySelector('.finding-body');if(fb)text+=fb.textContent.toLowerCase();
    var show=rm&&(!searchTerm||text.indexOf(searchTerm)!==-1);
    card.style.display=show?'':'none';if(show)visible++;
  });
  document.getElementById('results-label').textContent=
    'Showing '+visible+' of '+cards.length+' findings — click any row to expand';
  document.getElementById('no-results').style.display=visible===0?'block':'none';
}
function exportCSV(){
  var rows=[['Risk','Rule ID','Title','Category','MITRE ATT&CK','Affected Count','Description']];
  document.querySelectorAll('.finding-card').forEach(function(card){
    var risk=(card.querySelector('.risk-pill')||{}).textContent||'';
    var ruleId=(card.querySelector('.rule-id')||{}).textContent||'';
    var title=(card.querySelector('.finding-title')||{}).textContent||'';
    var cat=(card.querySelector('.cat-tag')||{}).textContent||'';
    var ttp=(card.querySelector('.ttp-link')||{}).textContent||'';
    var cnt=(card.querySelector('.data-count')||{}).textContent||'';
    var desc=(card.querySelector('.finding-desc')||{}).textContent.trim()||'';
    rows.push([risk,ruleId,title,cat,ttp,cnt,desc]);
  });
  var csv=rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"';}).join(',');}).join('\r\n');
  var blob=new Blob([csv],{type:'text/csv'}),a=document.createElement('a');
  a.href=URL.createObjectURL(blob);a.download='AzureADRecon-Findings.csv';a.click();
}
applyFilters();
</script>
</body>
</html>
"@
    $html | Out-File -FilePath $Out -Encoding UTF8
}

#endregion

#region ── Main Execution ──────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "  ║  AzureAD-Recon  —  Entra ID Security Audit Tool       ║" -ForegroundColor Blue
Write-Host "  ║               by Harsh P  |  github.com/MrHarshvardhan                 ║" -ForegroundColor Blue
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""

# Authenticate
try {
    $authMode = Get-GraphToken
} catch {
    Write-Host "  [ERROR] Authentication failed: $_" -ForegroundColor Red
    exit 1
}

$checks = @(
    @{ Name='TenantInfo';         Fn={ Invoke-CheckTenantInfo } }
    @{ Name='Roles';              Fn={ Invoke-CheckPrivilegedRoles } }
    @{ Name='MFA';                Fn={ Invoke-CheckMFA } }
    @{ Name='ConditionalAccess';  Fn={ Invoke-CheckConditionalAccess } }
    @{ Name='Applications';       Fn={ Invoke-CheckApplications } }
    @{ Name='GuestSettings';      Fn={ Invoke-CheckGuestSettings } }
    @{ Name='AuthMethods';        Fn={ Invoke-CheckAuthMethods } }
    @{ Name='HybridIdentity';     Fn={ Invoke-CheckHybridIdentity } }
    @{ Name='PIM';                Fn={ Invoke-CheckPIM } }
    @{ Name='RiskyUsers';         Fn={ Invoke-CheckRiskyUsers } }
    @{ Name='Domains';            Fn={ Invoke-CheckDomains } }
    @{ Name='UserInventory';      Fn={ Invoke-CheckUserInventory } }
    @{ Name='OAuthConsents';      Fn={ Invoke-CheckOAuthConsents } }
    @{ Name='Devices';            Fn={ Invoke-CheckDevices } }
    @{ Name='SSPR';               Fn={ Invoke-CheckSSPR } }
    @{ Name='AdminAccounts';      Fn={ Invoke-CheckAdminAccounts } }
    @{ Name='SignInFrequency';    Fn={ Invoke-CheckSignInFrequency } }
    @{ Name='SPCertificates';     Fn={ Invoke-CheckSPCertificates } }
    @{ Name='GroupSettings';      Fn={ Invoke-CheckGroupSettings } }
    @{ Name='CrossTenantAccess';  Fn={ Invoke-CheckCrossTenantAccess } }
    @{ Name='BreakGlass';         Fn={ Invoke-CheckBreakGlassAccounts } }
)

foreach ($check in $checks) {
    if ($SkipChecks -contains $check.Name) {
        Write-Host "  [--] Skipping: $($check.Name)" -ForegroundColor DarkGray
        continue
    }
    try {
        & $check.Fn
    } catch {
        $errMsg  = $_.Exception.Message
        $errLine = $_.InvocationInfo.ScriptLineNumber
        Write-Host "  [!] Module '$($check.Name)' failed (line $errLine): $errMsg" -ForegroundColor Red
        $Script:FailedModules.Add(@{ Name=$check.Name; Error=$errMsg; Line=$errLine }) | Out-Null
    }
}

$timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportFile = Join-Path $OutputPath "AzureADRecon_$($Script:TenantData['TenantId'])_${timestamp}.html"
Write-Status "Generating HTML report..."
New-HTMLReport -Out $reportFile

$score = Get-RiskScore
$crit  = ($Script:Findings | Where-Object Risk -eq 'Critical').Count
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "  ║           AzureAD-Recon Results  —  by Harsh P         ║" -ForegroundColor Blue
Write-Host "  ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Blue
Write-Host "  ║  Security Score : $($score.ToString().PadRight(37))║" -ForegroundColor (if($score -ge 70){'Green'}elseif($score -ge 40){'Yellow'}else{'Red'})
Write-Host "  ║  Findings       : $($Script:Findings.Count) ($crit Critical)".PadRight(58)  "║" -ForegroundColor Blue
Write-Host "  ║  Report Saved   : $(Split-Path $reportFile -Leaf)" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""

#endregion
