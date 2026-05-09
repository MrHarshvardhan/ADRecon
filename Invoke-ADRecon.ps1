#Requires -Version 5.1
<#
  ╔══════════════════════════════════════════════════════════════════════════╗
  ║          AD-Recon  —  Active Directory Security Audit Tool        ║
  ║                        by  Harsh P  |  github.com/MrHarshvardhan                      ║
  ║              Community Edition  |  github.com/MrHarshvardhan                   ║
  ╚══════════════════════════════════════════════════════════════════════════╝

.SYNOPSIS
    AD-Recon by Harsh P  |  github.com/MrHarshvardhan — Full-coverage AD security audit with HTML report.
    Requires no third-party tools. Uses native ADSI / DirectorySearcher.

.DESCRIPTION
    Performs 27 security check modules against an Active Directory domain and
    generates a self-contained HTML report with risk scoring and remediation.
    Safe, read-only — performs no changes to the directory.

.PARAMETER Domain
    Target domain FQDN (e.g. corp.local). Defaults to the caller's domain.

.PARAMETER Server
    Specific DC FQDN or IP to query. Defaults to DNS auto-discovery.

.PARAMETER Username
    Username for alternate credentials (e.g. CORP\auditor).
    Leave empty to use the current session's identity.

.PARAMETER Password
    Plaintext password for alternate credentials.
    Leave empty to use the current session's identity.
    Alternatively pass a PSCredential via -Credential.

.PARAMETER Credential
    PSCredential object. Overrides -Username / -Password if both are provided.

.PARAMETER OutputPath
    Directory for the HTML report. Defaults to current directory.

.PARAMETER SkipChecks
    Comma-separated module names to skip. Valid values:
    DomainInfo, DomainControllers, Krbtgt, Users, Computers, Groups,
    BuiltinAccounts, Delegation, Kerberos, Security, GPOSecurity,
    GPPPasswords, ShadowCredentials, Trusts, PKI, Exchange, RODC,
    AzureAD, DNS, LAPS, DisplaySpecifiers, FinePwdPolicy, FSMO,
    BroadACL, SitesSubnets, BitLocker, DNSZones

.PARAMETER NoColor
    Disable coloured console output (useful for CI pipelines).

.EXAMPLE
    # Simplest usage — runs against current domain with current user
    .\Invoke-ADRecon.ps1

.EXAMPLE
    # Specify domain and DC, save report to custom path
    .\Invoke-ADRecon.ps1 -Domain corp.local -Server dc01.corp.local -OutputPath C:\Reports

.EXAMPLE
    # Alternate credentials via Username/Password parameters
    .\Invoke-ADRecon.ps1 -Domain corp.local -Username CORP\auditor -Password '<password>'

.EXAMPLE
    # Alternate credentials via PSCredential (interactive prompt)
    $cred = Get-Credential
    .\Invoke-ADRecon.ps1 -Domain corp.local -Credential $cred

.EXAMPLE
    # Skip slow modules
    .\Invoke-ADRecon.ps1 -SkipChecks GPOSecurity,GPPPasswords,Exchange
#>

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  QUICK CREDENTIAL SETUP — edit here if not running as a domain user   ║
# ╠══════════════════════════════════════════════════════════════════════════╣
# ║  Option A (command line — recommended):                                ║
# ║    .\Invoke-ADRecon.ps1 -Domain corp.local \                          ║
# ║                          -Username CORP\auditor \                     ║
# ║                          -Password '<password>'                        ║
# ║                                                                        ║
# ║  Option B (edit defaults below, then just run .\Invoke-ADRecon.ps1):  ║
# ║    $DefaultUsername = 'CORP\auditor'                                  ║
# ║    $DefaultPassword = '<password>'                                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝

[CmdletBinding()]
param(
    [string]$Domain      = '',
    [string]$Server      = '',
    [string]$Username    = '',          # e.g. CORP\auditor  or  auditor@corp.local
    [string]$Password    = '',          # Replace <password> with your password here
    [PSCredential]$Credential,
    [string]$OutputPath  = (Get-Location).Path,
    [string[]]$SkipChecks = @(),
    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'
$StartTime = Get-Date

# Build credential from Username/Password if supplied and no Credential object passed
if (-not $Credential -and $Username -ne '' -and $Password -ne '' -and $Password -ne '<password>') {
    $secPwd    = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($Username, $secPwd)
}

#region ── Helpers ─────────────────────────────────────────────────────────────

function Write-Status {
    param([string]$Msg, [string]$Color = 'Cyan')
    Write-Host "  [*] $Msg" -ForegroundColor $Color
}
function Write-Finding {
    param([string]$Msg)
    Write-Host "  [!] $Msg" -ForegroundColor Yellow
}
function Write-OK {
    param([string]$Msg)
    Write-Host "  [+] $Msg" -ForegroundColor Green
}

# FileTime integer → DateTime
function Convert-FileTime {
    param([object]$ft)
    try {
        $v = [long]$ft
        if ($v -le 0 -or $v -eq [long]::MaxValue) { return $null }
        return [DateTime]::FromFileTimeUtc($v).ToLocalTime()
    } catch { return $null }
}

# Days since a DateTime (null → 99999)
function Days-Ago {
    param([datetime]$d)
    return (New-TimeSpan -Start $d -End (Get-Date)).Days
}

# Build a DirectorySearcher
function New-Searcher {
    param(
        [string]$Filter,
        [string[]]$Props,
        [string]$SearchBase = $Script:NC,
        [string]$Scope = 'Subtree',
        [int]$SizeLimit = 0
    )
    $path = "LDAP://$Script:BindServer/$SearchBase"
    if ($Script:Cred) {
        $de = New-Object System.DirectoryServices.DirectoryEntry($path,
              $Script:Cred.UserName, $Script:Cred.GetNetworkCredential().Password)
    } else {
        $de = New-Object System.DirectoryServices.DirectoryEntry($path)
    }
    $s = New-Object System.DirectoryServices.DirectorySearcher($de)
    $s.Filter      = $Filter
    $s.PageSize    = 500
    $s.SearchScope = $Scope
    if ($SizeLimit -gt 0) { $s.SizeLimit = $SizeLimit }
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    return $s
}

# Run a searcher and return property bags
function Invoke-Searcher {
    param(
        [string]$Filter,
        [string[]]$Props,
        [string]$SearchBase = $Script:NC,
        [string]$Scope = 'Subtree'
    )
    try {
        $s = New-Searcher -Filter $Filter -Props $Props -SearchBase $SearchBase -Scope $Scope
        return $s.FindAll()
    } catch {
        Write-Verbose "Searcher error: $_"
        return @()
    }
}

# Get single-value string property from result
function Get-Prop {
    param($Result, [string]$Name)
    try { return $Result.Properties[$Name][0] } catch { return $null }
}

# UAC bit test
function Test-UAC {
    param([object]$uac, [int]$bit)
    return (([int]$uac) -band $bit) -ne 0
}

# HTML-encode
function HE([string]$s) {
    return [System.Web.HttpUtility]::HtmlEncode($s)
}

# Score helpers
$Script:Findings = [System.Collections.Generic.List[hashtable]]::new()

# MITRE ATT&CK TTP mapping — exact RuleId match
$Script:MitreTTPMap = @{
    # Domain / Policy
    'S-MachineAccountQuota'     = 'T1136.002'   # Create Account: Domain Account
    'P-MinPwdLength'            = 'T1110.001'   # Brute Force: Password Guessing
    'P-NoLockout'               = 'T1110.001'
    'A-RecycleBin'              = 'T1070.001'   # Indicator Removal
    # DCs / OS
    'S-OldDCOS'                 = 'T1190'       # Exploit Public-Facing Application
    'S-EOLOS'                   = 'T1190'
    # Krbtgt / Kerberos
    'P-Krbtgt'                  = 'T1558.001'   # Golden Ticket
    'P-Kerberoast'              = 'T1558.003'   # Kerberoasting
    'P-ASREPRoast'              = 'T1558.004'   # AS-REP Roasting
    'S-DES-DC'                  = 'T1558.003'
    'S-RC4-DC'                  = 'T1558.003'
    'S-NoAES-DC'                = 'T1558.003'
    'S-RC4ServiceAcct'          = 'T1558.003'
    # Users / Accounts
    'P-AdminPwdAge'             = 'T1078.002'   # Valid Accounts: Domain Accounts
    'S-StaleUser'               = 'T1078.002'
    'P-SIDHistory'              = 'T1134.005'   # Token Impersonation: SID-History Injection
    'P-LAPS'                    = 'T1078.002'
    'P-LAPSNotInstalled'        = 'T1078.002'
    'P-PrivNoExpiry'            = 'T1078.002'
    'P-PasswordNotRequired'     = 'T1078.002'
    'P-ReversibleEncryption'    = 'T1003.001'   # OS Credential Dumping: LSASS Memory
    'P-DESOnly'                 = 'T1558.003'
    'P-PreWin2000'              = 'T1078.002'
    'P-AdminOutOU'              = 'T1484.001'   # Domain Policy Modification
    'P-WeakPSO'                 = 'T1110.001'
    'P-EnterpriseAdmins'        = 'T1078.002'
    'P-ProtectedUsers'          = 'T1078.002'
    # Computers
    'S-StaleComp'               = 'T1078.002'
    # Groups
    'P-DNSAdmins'               = 'T1484.001'
    'P-SchemaAdmins'            = 'T1484.001'
    # Delegation
    'P-UnconstrainedDelegation' = 'T1134.001'   # Token Impersonation/Theft
    'P-ConstrainedS4U'          = 'T1558.003'
    # DCSync / Privilege
    'S-DCSync'                  = 'T1003.006'   # OS Credential Dumping: DCSync
    # Trusts
    'T-SIDFilter'               = 'T1134.005'
    'T-NT4Trust'                = 'T1199'       # Trusted Relationship
    # PKI / ADCS
    'S-ESC1'                    = 'T1649'       # Steal or Forge Auth Certificates
    'S-ESC2'                    = 'T1649'
    'S-ESC3'                    = 'T1649'
    'S-ESC6'                    = 'T1649'
    'S-ESC8'                    = 'T1649'
    # Security Settings
    'S-WDigest'                 = 'T1003.001'   # LSASS credential dumping
    'S-LMLevel'                 = 'T1557.001'   # LLMNR/NTB-NS Poisoning
    'S-SMBSigning'              = 'T1557.001'   # Adversary-in-the-Middle
    'S-LDAPSigning'             = 'T1557.001'
    'S-PointPrint'              = 'T1068'       # Exploitation for Privilege Escalation
    'A-PSLogging'               = 'T1562.001'   # Impair Defenses: Disable/Modify Tools
    # Anonymity / Null session
    'A-AnonNSPI'                = 'T1135'       # Network Share Discovery
    'A-UnixPwd'                 = 'T1003.001'
    'A-JavaObject'              = 'T1574'       # Hijack Execution Flow
    # GPP / Passwords
    'S-GPPPassword'             = 'T1552.006'   # Unsecured Credentials: Group Policy Prefs
    # Exchange
    'S-ExchangeWriteDACL'       = 'T1558.001'
    'S-ExchangeTrustedSubsystem'= 'T1558.001'
    # ADCS Extended
    # RODC
    'S-RODCPrivReplication'     = 'T1003.006'
    'S-RODCManyRevealed'        = 'T1003.006'
    # Shadow Credentials
    'S-ShadowCreds'             = 'T1556.006'   # Modify Authentication Process
    # Azure AD Connect
    'S-AzureSSOAge'             = 'T1078.004'   # Valid Accounts: Cloud Accounts
    'S-MSOLAccount'             = 'T1078.004'
    # DNS
    'A-WPAD'                    = 'T1557.001'
    'A-DNSWildcard'             = 'T1557.001'
    'S-DNSAdmins'               = 'T1484.001'
    # LAPS ACL
    'S-LAPSOpenRead'            = 'T1078.002'
    # Display Specifiers
    'A-DisplaySpecifier'        = 'T1059.001'   # PowerShell / Script execution
    # Built-in Accounts
    'A-GuestEnabled'            = 'T1078.003'   # Valid Accounts: Local Accounts
    'A-AdminNotRenamed'         = 'T1078.003'
    'A-AdminPwdAge'             = 'T1078.003'
    # New modules
    'S-DangerousACE'            = 'T1484.001'   # Domain Policy Modification via ACE
    'A-OrphanSubnet'            = 'T1016'       # System Network Configuration Discovery
    'A-MissingSubnets'          = 'T1016'
    'S-BitLockerACL'            = 'T1552.001'   # Unsecured Credentials: Credentials in Files
    'S-DNSZoneUnsigned'         = 'T1557.002'   # AiTM: DNS Spoofing
    'A-DNSZoneInventory'        = 'T1590.002'   # Gather Victim Network Info: DNS
    'S-OrphanAdminCount'        = 'T1078.001'   # Valid Accounts: ghost privilege artefact
    'S-PrintSpoolerDC'          = 'T1187'        # Forced Authentication via SpoolSS
    'S-InactiveGPO'             = 'T1484.001'   # Domain Policy Modification via unlinked GPO
    'S-OrphanFSP'               = 'T1078.002'   # Valid Accounts: Domain Accounts (FSP remnants)
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$RuleId,
        [string]$Title,
        [string]$Risk,       # Critical / High / Medium / Low / Info
        [string]$Detail,
        [string]$Remediation,
        [object]$Data = $null
    )
    $Script:Findings.Add(@{
        Category    = $Category
        RuleId      = $RuleId
        Title       = $Title
        Risk        = $Risk
        Detail      = $Detail
        Remediation = $Remediation
        Data        = $Data
    })
}

#endregion

#region ── Connection Setup ────────────────────────────────────────────────────

$c = if ($NoColor) { @{} } else { @{ForegroundColor='Magenta'} }
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" @c
Write-Host "  ║   AD-Recon  —  Active Directory Security Audit       ║" @c
Write-Host "  ║                  by Harsh P  |  github.com/MrHarshvardhan              ║" @c
Write-Host "  ╚══════════════════════════════════════════════════════════╝" @c
Write-Host ""

$Script:Cred = $Credential

# Resolve domain / server
if ([string]::IsNullOrEmpty($Domain)) {
    try {
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    } catch {
        $Domain = $env:USERDNSDOMAIN
    }
}
if ([string]::IsNullOrEmpty($Server)) {
    $Script:BindServer = $Domain
} else {
    $Script:BindServer = $Server
}

Write-Status "Connecting to domain: $Domain via $Script:BindServer"

# Get RootDSE
try {
    $rootPath = "LDAP://$Script:BindServer/RootDSE"
    if ($Script:Cred) {
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry($rootPath,
                   $Script:Cred.UserName, $Script:Cred.GetNetworkCredential().Password)
    } else {
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry($rootPath)
    }
    $Script:NC     = $rootDSE.Properties['defaultNamingContext'][0]
    $Script:Config = $rootDSE.Properties['configurationNamingContext'][0]
    $Script:Schema = $rootDSE.Properties['schemaNamingContext'][0]
    $Script:Forest = $rootDSE.Properties['rootDomainNamingContext'][0]
    Write-OK "Connected. NC: $Script:NC"
} catch {
    Write-Host "`n  [ERROR] Cannot connect to $Script:BindServer : $_" -ForegroundColor Red
    exit 1
}

#endregion

#region ── CHECK: Domain Info ──────────────────────────────────────────────────

$Script:DomainInfo = @{}

function Invoke-CheckDomainInfo {
    Write-Status "Collecting domain information..."

    $res = Invoke-Searcher -Filter "(&(objectClass=domain)(distinguishedName=$Script:NC))" `
           -Props @('objectSid','whenCreated','ms-DS-MachineAccountQuota',
                    'msDS-Behavior-Version','msDS-ExpirePasswordsOnSmartCardOnlyAccounts',
                    'pwdHistoryLength','minPwdLength','maxPwdAge','minPwdAge',
                    'lockoutThreshold','lockoutDuration','lockoutObservationWindow',
                    'pwdProperties','whenChanged') `
           -Scope 'Base'

    if ($res.Count -gt 0) {
        $r = $res[0]
        $Script:DomainInfo['SID']             = (Get-Prop $r 'objectsid') -as [System.Security.Principal.SecurityIdentifier]
        $Script:DomainInfo['Created']          = Convert-FileTime (Get-Prop $r 'whencreated')
        $Script:DomainInfo['MAQ']              = Get-Prop $r 'ms-ds-machineaccountquota'
        $Script:DomainInfo['FunctionalLevel']  = Get-Prop $r 'msds-behavior-version'
        $Script:DomainInfo['MinPwdLength']     = Get-Prop $r 'minpwdlength'
        $Script:DomainInfo['PwdHistory']       = Get-Prop $r 'pwdhistorylength'
        $Script:DomainInfo['PwdComplexity']    = (([int](Get-Prop $r 'pwdproperties') -band 1) -ne 0)
        $Script:DomainInfo['LockoutThreshold'] = Get-Prop $r 'lockoutthreshold'
        $Script:DomainInfo['MaxPwdAge']        = [Math]::Abs([long](Get-Prop $r 'maxpwdage')) / 864000000000

        # MAQ check
        $maq = [int]$Script:DomainInfo['MAQ']
        if ($maq -ne 0) {
            Add-Finding -Category 'Security' -RuleId 'S-MachineAccountQuota' `
                -Title 'Machine Account Quota allows non-admins to join computers' `
                -Risk 'High' `
                -Detail "ms-DS-MachineAccountQuota = $maq. Any domain user can create up to $maq computer accounts, enabling RBCD attacks." `
                -Remediation 'Set ms-DS-MachineAccountQuota to 0 via: Set-ADDomain -Identity . -Replace @{"ms-DS-MachineAccountQuota"=0}'
        }

        # Password policy
        $minLen = [int]$Script:DomainInfo['MinPwdLength']
        if ($minLen -lt 12) {
            Add-Finding -Category 'Accounts' -RuleId 'P-MinPwdLength' `
                -Title "Default password policy: minimum length too short ($minLen chars)" `
                -Risk (if ($minLen -lt 8) { 'Critical' } else { 'Medium' }) `
                -Detail "Minimum password length is $minLen characters in the default domain policy." `
                -Remediation 'Set minimum password length to at least 12 (prefer 14+). Use Fine-Grained Password Policies for admin accounts.'
        }

        $lockout = [int]$Script:DomainInfo['LockoutThreshold']
        if ($lockout -eq 0) {
            Add-Finding -Category 'Accounts' -RuleId 'P-NoLockout' `
                -Title 'No account lockout policy configured' `
                -Risk 'High' `
                -Detail 'Lockout threshold = 0, allowing unlimited password brute-force attempts.' `
                -Remediation 'Set lockout threshold to 5-10 attempts. Consider Microsoft Entra Password Protection for DC.'
        }
    }

    # Schema version
    $schRes = Invoke-Searcher -Filter '(objectClass=dMD)' `
              -Props @('objectVersion') -SearchBase $Script:Schema -Scope 'Base'
    if ($schRes.Count -gt 0) {
        $Script:DomainInfo['SchemaVersion'] = Get-Prop $schRes[0] 'objectversion'
    }

    # Forest functional level
    $flRes = Invoke-Searcher -Filter '(objectClass=crossRefContainer)' `
             -Props @('msDS-Behavior-Version') `
             -SearchBase "CN=Partitions,$Script:Config" -Scope 'Base'
    if ($flRes.Count -gt 0) {
        $Script:DomainInfo['ForestFL'] = Get-Prop $flRes[0] 'msds-behavior-version'
    }

    # Recycle Bin
    $rbRes = Invoke-Searcher `
             -Filter '(name=Recycle Bin Feature)' `
             -Props @('msDS-EnabledFeature') `
             -SearchBase "CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$Script:Config"
    $Script:DomainInfo['RecycleBin'] = ($rbRes.Count -gt 0)
    if (-not $Script:DomainInfo['RecycleBin']) {
        Add-Finding -Category 'Anomalies' -RuleId 'A-RecycleBin' `
            -Title 'AD Recycle Bin not enabled' `
            -Risk 'Medium' `
            -Detail 'Without Recycle Bin, accidentally deleted AD objects cannot be recovered without authoritative restore.' `
            -Remediation 'Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name'
    }

    Write-OK "Domain info collected"
}

#endregion

#region ── CHECK: Domain Controllers ──────────────────────────────────────────

$Script:DCList = @()

function Invoke-CheckDomainControllers {
    Write-Status "Enumerating Domain Controllers..."

    $res = Invoke-Searcher `
           -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' `
           -Props @('name','dNSHostName','operatingSystem','operatingSystemVersion',
                    'whenCreated','lastLogonTimestamp','userAccountControl',
                    'msDS-IsRODC','distinguishedName')

    $dcList = foreach ($r in $res) {
        $uac     = [int](Get-Prop $r 'useraccountcontrol')
        $isRODC  = Test-UAC $uac 0x4000000
        $lastLL  = Convert-FileTime (Get-Prop $r 'lastlogontimestamp')
        @{
            Name       = Get-Prop $r 'name'
            DNS        = Get-Prop $r 'dnshostname'
            OS         = Get-Prop $r 'operatingSystem'
            OSVersion  = Get-Prop $r 'operatingsystemversion'
            Created    = Convert-FileTime (Get-Prop $r 'whencreated')
            LastLogon  = $lastLL
            IsRODC     = $isRODC
            DN         = Get-Prop $r 'distinguishedname'
        }
    }
    $Script:DCList = @($dcList)
    Write-OK "Found $($Script:DCList.Count) Domain Controller(s)"

    # Check for old DC OS
    foreach ($dc in $Script:DCList) {
        $os = $dc.OS
        if ($os -match '2003|2000|2008') {
            Add-Finding -Category 'Stale' -RuleId 'S-OldDCOS' `
                -Title "Domain Controller running EOL OS: $($dc.Name)" `
                -Risk 'Critical' `
                -Detail "DC $($dc.Name) runs $os which is end-of-life and receives no security patches." `
                -Remediation 'Upgrade or decommission this DC immediately.'
        }
    }

    # WebDAV/WebClient pipe check (indicative — just flag for manual check)
    Write-OK "DC enumeration complete"
}

#endregion

#region ── CHECK: Krbtgt ───────────────────────────────────────────────────────

function Invoke-CheckKrbtgt {
    Write-Status "Checking krbtgt account..."

    $res = Invoke-Searcher `
           -Filter '(sAMAccountName=krbtgt)' `
           -Props @('pwdLastSet','whenCreated','distinguishedName')

    if ($res.Count -gt 0) {
        $pwdSet = Convert-FileTime (Get-Prop $res[0] 'pwdlastset')
        $Script:DomainInfo['KrbtgtPwdAge'] = if ($pwdSet) { Days-Ago $pwdSet } else { 9999 }
        $age = $Script:DomainInfo['KrbtgtPwdAge']

        if ($age -gt 180) {
            Add-Finding -Category 'Accounts' -RuleId 'P-Krbtgt' `
                -Title "krbtgt password not changed in $age days" `
                -Risk (if ($age -gt 365) { 'Critical' } else { 'High' }) `
                -Detail "krbtgt password was last changed $age days ago (changed: $pwdSet). A stale krbtgt allows Golden Tickets to remain valid indefinitely." `
                -Remediation 'Reset krbtgt password twice (48 hours apart) using: https://github.com/microsoft/New-KrbtgtKeys.ps1'
        } else {
            Write-OK "krbtgt password age: $age days (OK)"
        }
    }
}

#endregion

#region ── CHECK: Users ────────────────────────────────────────────────────────

$Script:UserStats = @{ Total=0; Disabled=0; Stale=0; AdminCount=0; NeverExpires=0; NoPreAuth=0; SPN=0 }

function Invoke-CheckUsers {
    Write-Status "Enumerating user accounts..."

    $cutoff180  = (Get-Date).AddDays(-180)
    $cutoff90   = (Get-Date).AddDays(-90)
    $ft180      = $cutoff180.ToFileTimeUtc()

    $filter = '(|(&(objectClass=user)(objectCategory=person))(objectcategory=msDS-GroupManagedServiceAccount)(objectcategory=msDS-ManagedServiceAccount))'
    $props  = @('sAMAccountName','distinguishedName','userAccountControl','pwdLastSet',
                'lastLogonTimestamp','whenCreated','adminCount','servicePrincipalName',
                'sIDHistory','mail','primaryGroupID','objectClass')

    $res = Invoke-Searcher -Filter $filter -Props $props

    $staleUsers    = [System.Collections.Generic.List[hashtable]]::new()
    $adminUsers    = [System.Collections.Generic.List[hashtable]]::new()
    $kerbUsers     = [System.Collections.Generic.List[hashtable]]::new()
    $asrepUsers    = [System.Collections.Generic.List[hashtable]]::new()
    $sidHistUsers  = [System.Collections.Generic.List[hashtable]]::new()
    $noPwdExpUsers = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($r in $res) {
        $sam  = Get-Prop $r 'samaccountname'
        $uac  = [int](Get-Prop $r 'useraccountcontrol')
        $spns = $r.Properties['serviceprincipalname']
        $sidH = $r.Properties['sidhistory']

        $Script:UserStats.Total++

        $disabled = Test-UAC $uac 0x2
        if ($disabled) { $Script:UserStats.Disabled++; continue }

        $pwdSet  = Convert-FileTime (Get-Prop $r 'pwdlastset')
        $lastLL  = Convert-FileTime (Get-Prop $r 'lastlogontimestamp')
        $created = Convert-FileTime (Get-Prop $r 'whencreated')
        $admin   = Get-Prop $r 'admincount'
        $dn      = Get-Prop $r 'distinguishedname'

        # Stale accounts (no logon > 180 days, or never logged in > 90 days old)
        $isStale = $false
        if ($lastLL -and (Days-Ago $lastLL) -gt 180) { $isStale = $true }
        elseif (-not $lastLL -and $created -and (Days-Ago $created) -gt 90) { $isStale = $true }
        if ($isStale) {
            $Script:UserStats.Stale++
            $staleUsers.Add(@{ Sam=$sam; DN=$dn; LastLogon=$lastLL; Created=$created }) | Out-Null
        }

        # AdminCount=1
        if ([int]$admin -eq 1 -and $sam -ne 'krbtgt') {
            $Script:UserStats.AdminCount++
            $adminUsers.Add(@{ Sam=$sam; DN=$dn; PwdSet=$pwdSet; LastLogon=$lastLL }) | Out-Null
        }

        # No expiry password
        if (Test-UAC $uac 0x10000) {
            $Script:UserStats.NeverExpires++
            $noPwdExpUsers.Add(@{ Sam=$sam; DN=$dn }) | Out-Null
        }

        # AS-REP Roastable (no pre-auth)
        if (Test-UAC $uac 0x400000) {
            $Script:UserStats.NoPreAuth++
            $asrepUsers.Add(@{ Sam=$sam; DN=$dn }) | Out-Null
        }

        # Kerberoastable (SPN set, not a computer)
        if ($spns -and $spns.Count -gt 0 -and $sam -notmatch '\$$') {
            $Script:UserStats.SPN++
            $kerbUsers.Add(@{ Sam=$sam; DN=$dn; SPNs=($spns -join ', '); PwdSet=$pwdSet }) | Out-Null
        }

        # SID History
        if ($sidH -and $sidH.Count -gt 0) {
            $sidHistUsers.Add(@{ Sam=$sam; DN=$dn }) | Out-Null
        }
    }

    Write-OK "Users: $($Script:UserStats.Total) total, $($Script:UserStats.Disabled) disabled"

    # --- AdminSDHolder / AdminCount findings ---
    $pwdThreshold = 365
    $staleAdmins = $adminUsers | Where-Object {
        $a = $_
        if (-not $a.PwdSet) { return $true }
        (Days-Ago $a.PwdSet) -gt $pwdThreshold
    }
    if ($staleAdmins.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-AdminPwdAge' `
            -Title "Privileged accounts with passwords older than $pwdThreshold days" `
            -Risk 'High' `
            -Detail "$($staleAdmins.Count) accounts with adminCount=1 have not changed passwords in over a year." `
            -Remediation 'Enforce regular password rotation for privileged accounts. Implement tiered administration model.' `
            -Data $staleAdmins
    }
    $Script:AdminUsers = $adminUsers

    # --- Kerberoastable ---
    if ($kerbUsers.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-Kerberoast' `
            -Title "$($kerbUsers.Count) Kerberoastable account(s) found" `
            -Risk (if ($kerbUsers.Count -gt 5) { 'High' } else { 'Medium' }) `
            -Detail "These accounts have SPNs and are vulnerable to offline password cracking via TGS ticket requests." `
            -Remediation 'Use gMSA accounts for services. Ensure affected accounts have long (25+ char) random passwords. Remove unnecessary SPNs.' `
            -Data $kerbUsers
    }

    # --- AS-REP Roastable ---
    if ($asrepUsers.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-ASREPRoast' `
            -Title "$($asrepUsers.Count) AS-REP Roastable account(s) found" `
            -Risk 'High' `
            -Detail 'Accounts with "Do not require Kerberos preauthentication" — AS-REP hash can be cracked offline without authentication.' `
            -Remediation 'Enable Kerberos pre-authentication on all accounts unless explicitly required.' `
            -Data $asrepUsers
    }

    # --- Stale users ---
    if ($staleUsers.Count -gt 0) {
        $pct = [Math]::Round(($staleUsers.Count / [Math]::Max($Script:UserStats.Total,1)) * 100)
        Add-Finding -Category 'Stale' -RuleId 'S-StaleUser' `
            -Title "$($staleUsers.Count) stale enabled user accounts ($pct%)" `
            -Risk (if ($pct -gt 20) { 'High' } elseif ($pct -gt 5) { 'Medium' } else { 'Low' }) `
            -Detail "Enabled user accounts with no logon in 180+ days. These are attack surface for credential attacks." `
            -Remediation 'Disable or delete accounts inactive for 90+ days. Implement a joiners/movers/leavers process.' `
            -Data ($staleUsers | Select-Object -First 20)
    }

    # --- SID History ---
    if ($sidHistUsers.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-SIDHistory' `
            -Title "$($sidHistUsers.Count) account(s) with SID History" `
            -Risk 'Medium' `
            -Detail 'SID History enables cross-domain privilege escalation if the historical SID belonged to a privileged group.' `
            -Remediation 'Audit and remove unnecessary SID History entries. Verify each entry is intentional post-migration.' `
            -Data $sidHistUsers
    }

    Write-OK "User checks complete. Kerberoastable:$($kerbUsers.Count) ASREP:$($asrepUsers.Count)"
}

#endregion

#region ── CHECK: Computers ────────────────────────────────────────────────────

$Script:ComputerStats = @{ Total=0; Disabled=0; Stale=0; LAPSCovered=0 }

function Invoke-CheckComputers {
    Write-Status "Enumerating computer accounts..."

    $res = Invoke-Searcher `
           -Filter '(objectCategory=computer)' `
           -Props @('sAMAccountName','distinguishedName','operatingSystem',
                    'operatingSystemVersion','userAccountControl','lastLogonTimestamp',
                    'whenCreated','pwdLastSet','ms-Mcs-AdmPwdExpirationTime',
                    'msLAPS-PasswordExpirationTime','servicePrincipalName',
                    'msDS-IsRODC','primaryGroupID')

    $staleComps  = [System.Collections.Generic.List[hashtable]]::new()
    $eolOS       = [System.Collections.Generic.List[hashtable]]::new()
    $noLAPS      = [System.Collections.Generic.List[hashtable]]::new()
    $osCounts    = @{}
    $lapsCount   = 0
    $workstations= 0
    $servers     = 0

    $eolPatterns = 'Windows XP|Windows 2000|Windows Vista|Server 2003|Server 2008 R2|Server 2008[^R]|Windows 7|Windows 8[^.]'

    foreach ($r in $res) {
        $uac  = [int](Get-Prop $r 'useraccountcontrol')
        if (Test-UAC $uac 0x2) { $Script:ComputerStats.Disabled++; continue }

        # Skip DCs (primaryGroupID 516 = DC, 521 = RODC)
        $pgid = [int](Get-Prop $r 'primarygroupid')
        if ($pgid -eq 516 -or $pgid -eq 521) { continue }

        $Script:ComputerStats.Total++
        $sam     = Get-Prop $r 'samaccountname'
        $dn      = Get-Prop $r 'distinguishedname'
        $os      = Get-Prop $r 'operatingsystem'
        $lastLL  = Convert-FileTime (Get-Prop $r 'lastlogontimestamp')
        $created = Convert-FileTime (Get-Prop $r 'whencreated')

        # OS inventory
        if ($os) {
            $osKey = $os -replace '\s+\(.*\)',''
            if (-not $osCounts[$osKey]) { $osCounts[$osKey] = 0 }
            $osCounts[$osKey]++
            if ($os -match 'Server') { $servers++ } else { $workstations++ }
        }

        # Stale
        $isStale = $false
        if ($lastLL -and (Days-Ago $lastLL) -gt 180) { $isStale = $true }
        elseif (-not $lastLL -and $created -and (Days-Ago $created) -gt 90) { $isStale = $true }
        if ($isStale) {
            $Script:ComputerStats.Stale++
            $staleComps.Add(@{ Sam=$sam; DN=$dn; OS=$os; LastLogon=$lastLL }) | Out-Null
        }

        # EOL OS
        if ($os -match $eolPatterns) {
            $eolOS.Add(@{ Sam=$sam; DN=$dn; OS=$os }) | Out-Null
        }

        # LAPS coverage (legacy ms-Mcs-AdmPwd or new msLAPS)
        $lapsLegacy = $r.Properties['ms-mcs-admpwdexpirationtime']
        $lapsNew    = $r.Properties['mslaps-passwordexpirationtime']
        $hasLAPS    = ($lapsLegacy -and $lapsLegacy.Count -gt 0) -or ($lapsNew -and $lapsNew.Count -gt 0)
        if ($hasLAPS) { $lapsCount++ } else { $noLAPS.Add(@{ Sam=$sam; DN=$dn; OS=$os }) | Out-Null }
    }

    $Script:ComputerStats.LAPSCovered = $lapsCount
    $Script:OsCounts = $osCounts

    # Stale computers
    if ($staleComps.Count -gt 0) {
        $pct = [Math]::Round(($staleComps.Count / [Math]::Max($Script:ComputerStats.Total,1)) * 100)
        Add-Finding -Category 'Stale' -RuleId 'S-StaleComp' `
            -Title "$($staleComps.Count) stale enabled computer accounts ($pct%)" `
            -Risk (if ($pct -gt 20) { 'High' } elseif ($pct -gt 5) { 'Medium' } else { 'Low' }) `
            -Detail 'Stale computer accounts can be exploited to forge Kerberos tickets or abuse RBCD.' `
            -Remediation 'Disable or delete computer accounts inactive for 90+ days. Automate via Group Policy.' `
            -Data ($staleComps | Select-Object -First 20)
    }

    # EOL OS
    if ($eolOS.Count -gt 0) {
        Add-Finding -Category 'Stale' -RuleId 'S-EOLOS' `
            -Title "$($eolOS.Count) computer(s) running end-of-life OS" `
            -Risk 'Critical' `
            -Detail "EOL operating systems receive no security patches. Found: $(($eolOS | Group-Object -Property OS | ForEach-Object {"$($_.Name): $($_.Count)"}) -join ', ')" `
            -Remediation 'Upgrade or isolate all EOL systems. Prioritize network segmentation.' `
            -Data ($eolOS | Select-Object -First 20)
    }

    # LAPS coverage
    $total = $Script:ComputerStats.Total
    if ($total -gt 0) {
        $lapsPct = [Math]::Round(($lapsCount / $total) * 100)
        if ($lapsPct -lt 100) {
            Add-Finding -Category 'Accounts' -RuleId 'P-LAPS' `
                -Title "LAPS not deployed on $($noLAPS.Count) computer(s) ($lapsPct% coverage)" `
                -Risk (if ($lapsPct -lt 50) { 'High' } else { 'Medium' }) `
                -Detail "Without LAPS, local Administrator passwords may be shared/reused across machines enabling lateral movement." `
                -Remediation 'Deploy Windows LAPS (built-in, Windows Server 2019+/Win10+) or legacy LAPS MSI for older systems.' `
                -Data ($noLAPS | Select-Object -First 20)
        } else {
            Write-OK "LAPS: 100% coverage"
        }
    }

    Write-OK "Computers: $($Script:ComputerStats.Total) active ($servers servers, $workstations workstations)"
}

#endregion

#region ── CHECK: Privileged Groups ──────────────────────────────────────────

function Invoke-CheckGroups {
    Write-Status "Checking privileged groups..."

    # Pre-Windows 2000 Compatible Access (S-1-5-32-554)
    $res = Invoke-Searcher `
           -Filter '(objectSid=S-1-5-32-554)' `
           -Props @('member','distinguishedName') `
           -SearchBase "CN=Builtin,$Script:NC"

    if ($res.Count -gt 0) {
        $members = $res[0].Properties['member']
        if ($members -and $members.Count -gt 0) {
            # Check if "Everyone" or "Authenticated Users" (anonymous access indication)
            $dangerous = $members | Where-Object { $_ -match 'S-1-1-0|S-1-5-11|CN=S-1-' }
            Add-Finding -Category 'Accounts' -RuleId 'P-PreWin2000' `
                -Title "Pre-Windows 2000 Compatible Access group has $($members.Count) member(s)" `
                -Risk 'High' `
                -Detail 'Membership in this group grants anonymous/unauthenticated read access to many AD attributes (null session enumeration).' `
                -Remediation 'Remove all members from "Pre-Windows 2000 Compatible Access". Run: net localgroup "Pre-Windows 2000 Compatible Access" on DCs.' `
                -Data @($members)
        } else {
            Write-OK 'Pre-Windows 2000 group: empty (OK)'
        }
    }

    # DNSAdmins group — DLL injection path to SYSTEM on DC
    $dnsRes = Invoke-Searcher `
              -Filter '(sAMAccountName=DNSAdmins)' `
              -Props @('member','distinguishedName','whenCreated')
    if ($dnsRes.Count -gt 0) {
        $dnsMembers = $dnsRes[0].Properties['member']
        if ($dnsMembers -and $dnsMembers.Count -gt 0) {
            Add-Finding -Category 'Accounts' -RuleId 'P-DNSAdmins' `
                -Title "DNSAdmins group has $($dnsMembers.Count) member(s)" `
                -Risk 'High' `
                -Detail 'DNSAdmins members can load arbitrary DLLs into the DNS service (running as SYSTEM on DCs) — effective DC compromise.' `
                -Remediation 'Audit DNSAdmins membership. Remove non-essential members. Monitor for dnscmd.exe /config /serverlevelplugindll usage.' `
                -Data @($dnsMembers)
        }
    }

    # Schema Admins (should be empty except during schema upgrades)
    $schRes = Invoke-Searcher `
              -Filter '(sAMAccountName=Schema Admins)' `
              -Props @('member','distinguishedName')
    if ($schRes.Count -gt 0) {
        $schMembers = $schRes[0].Properties['member']
        if ($schMembers -and $schMembers.Count -gt 0) {
            Add-Finding -Category 'Accounts' -RuleId 'P-SchemaAdmins' `
                -Title "Schema Admins group is not empty ($($schMembers.Count) member(s))" `
                -Risk 'Medium' `
                -Detail 'Schema Admins should be empty when not performing schema upgrades. Members can modify the AD schema forest-wide.' `
                -Remediation 'Remove all members from Schema Admins. Add members only during planned schema upgrades, then remove immediately.' `
                -Data @($schMembers)
        } else {
            Write-OK 'Schema Admins: empty (OK)'
        }
    }

    Write-OK "Group checks complete"
}

#endregion

#region ── CHECK: Kerberos Delegation ─────────────────────────────────────────

function Invoke-CheckDelegation {
    Write-Status "Checking Kerberos delegation..."

    # Unconstrained delegation on non-DCs (UAC bit 0x80000)
    $res = Invoke-Searcher `
           -Filter '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))(!(primaryGroupID=521))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
           -Props @('sAMAccountName','distinguishedName','objectClass','operatingSystem')

    $unconstrained = foreach ($r in $res) {
        @{ Sam=(Get-Prop $r 'samaccountname'); DN=(Get-Prop $r 'distinguishedname'); Class=(Get-Prop $r 'objectclass') }
    }

    if ($unconstrained.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-UnconstrainedDelegation' `
            -Title "$($unconstrained.Count) object(s) with unconstrained Kerberos delegation" `
            -Risk 'Critical' `
            -Detail 'Unconstrained delegation allows the account/computer to impersonate ANY user to ANY service. Attackers with access to these systems can steal TGTs (e.g., via Printer Bug / SpoolSample).' `
            -Remediation 'Convert to constrained delegation or resource-based constrained delegation. Remove TrustedForDelegation flag.' `
            -Data $unconstrained
    }

    # Constrained delegation (msDS-AllowedToDelegateTo set)
    $res2 = Invoke-Searcher `
            -Filter '(&(msDS-AllowedToDelegateTo=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            -Props @('sAMAccountName','distinguishedName','msDS-AllowedToDelegateTo','userAccountControl')

    $constrained = foreach ($r in $res2) {
        $uac  = [int](Get-Prop $r 'useraccountcontrol')
        $s4u  = Test-UAC $uac 0x1000000
        $spns = $r.Properties['msds-allowedtodelegateto']
        @{
            Sam    = Get-Prop $r 'samaccountname'
            DN     = Get-Prop $r 'distinguishedname'
            SPNs   = ($spns -join '; ')
            S4U2Self = $s4u
        }
    }

    if ($constrained.Count -gt 0) {
        # Flag any with S4U2Self (protocol transition) — higher risk
        $protocolTransition = $constrained | Where-Object { $_.S4U2Self }
        if ($protocolTransition.Count -gt 0) {
            Add-Finding -Category 'Accounts' -RuleId 'P-ConstrainedS4U' `
                -Title "$($protocolTransition.Count) object(s) with constrained delegation + protocol transition" `
                -Risk 'High' `
                -Detail 'Protocol transition (TrustedToAuthForDelegation) allows the account to impersonate ANY user to the delegated services without a TGT.' `
                -Remediation 'Audit each entry. Remove protocol transition where not strictly required. Use gMSA accounts for services.' `
                -Data $protocolTransition
        }
    }

    Write-OK "Delegation checks complete. Unconstrained: $($unconstrained.Count)"
}

#endregion

#region ── CHECK: DCSync Rights ───────────────────────────────────────────────

function Invoke-CheckDCSync {
    Write-Status "Checking DCSync rights on domain root..."

    # GUIDs for replication extended rights
    $replChanges         = [GUID]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    $replChangesAll      = [GUID]'1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
    $replChangesFiltered = [GUID]'89e95b76-444d-4c62-991a-0facbeda640c'

    # Known safe SIDs (DCs, DA, EA, Administrators)
    $safeSids = @(
        'S-1-5-32-544',                    # BUILTIN\Administrators
        "$($Script:DomainInfo['SID'])-512", # Domain Admins
        "$($Script:DomainInfo['SID'])-516", # Domain Controllers
        "$($Script:DomainInfo['SID'])-518", # Schema Admins
        "$($Script:DomainInfo['SID'])-519", # Enterprise Admins
        "$($Script:DomainInfo['SID'])-521", # RODCs
        'S-1-5-18'                          # SYSTEM
    )

    try {
        $path = "AD:\$Script:NC"
        if (Get-Command Get-Acl -ErrorAction SilentlyContinue) {
            $acl = Get-Acl $path -ErrorAction Stop
            $suspicious = $acl.Access | Where-Object {
                $_.ActiveDirectoryRights -match 'ExtendedRight' -and
                ($_.ObjectType -eq $replChanges -or
                 $_.ObjectType -eq $replChangesAll -or
                 $_.ObjectType -eq $replChangesFiltered) -and
                $_.IdentityReference -notmatch 'NT AUTHORITY|Domain Controllers|Administrators|Domain Admins|Enterprise Admins|Schema Admins|ENTERPRISE DOMAIN CONTROLLERS'
            }

            if ($suspicious) {
                Add-Finding -Category 'Security' -RuleId 'S-DCSync' `
                    -Title "$($suspicious.Count) non-standard account(s) have DCSync rights" `
                    -Risk 'Critical' `
                    -Detail "The following identities have DS-Replication-Get-Changes rights on the domain root, enabling DCSync attacks to dump all password hashes:`n$(($suspicious | ForEach-Object { $_.IdentityReference.Value }) -join "`n")" `
                    -Remediation 'Remove replication rights from non-DC accounts. Investigate how these permissions were granted.' `
                    -Data @($suspicious | ForEach-Object { $_.IdentityReference.Value })
            } else {
                Write-OK "DCSync rights: no unexpected accounts found"
            }
        } else {
            Write-Status "Get-Acl/AD: provider not available — skipping DCSync ACL check" 'Yellow'
        }
    } catch {
        Write-Verbose "DCSync check error: $_"
    }
}

#endregion

#region ── CHECK: AdminSDHolder ───────────────────────────────────────────────

function Invoke-CheckAdminSDHolder {
    Write-Status "Checking AdminSDHolder and protected accounts..."

    $res = Invoke-Searcher `
           -Filter '(&(objectClass=user)(objectCategory=person)(admincount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))' `
           -Props @('sAMAccountName','distinguishedName','pwdLastSet','lastLogonTimestamp','whenCreated')

    $protected = foreach ($r in $res) {
        @{
            Sam      = Get-Prop $r 'samaccountname'
            DN       = Get-Prop $r 'distinguishedname'
            PwdSet   = Convert-FileTime (Get-Prop $r 'pwdlastset')
            LastLogon= Convert-FileTime (Get-Prop $r 'lastlogontimestamp')
        }
    }

    $Script:DomainInfo['ProtectedUserCount'] = $protected.Count

    # Check for accounts outside of expected privileged containers (Tier-0 hygiene)
    $ouside = $protected | Where-Object {
        $_.DN -notmatch 'CN=Users|OU=Privileged|OU=Admin|OU=Tier0|OU=Service'
    }

    if ($ouside.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-AdminOutOU' `
            -Title "$($ouside.Count) protected accounts found outside standard privileged OUs" `
            -Risk 'Medium' `
            -Detail 'Privileged accounts (adminCount=1) stored in non-privileged OUs may receive weaker GPO security settings.' `
            -Remediation 'Move privileged accounts to dedicated Tier-0 OU with restricted GPO and no logon rights to lower tiers.' `
            -Data $ouside
    }

    Write-OK "AdminSDHolder: $($protected.Count) protected account(s)"
}

#endregion

#region ── CHECK: Trusts ──────────────────────────────────────────────────────

function Invoke-CheckTrusts {
    Write-Status "Enumerating trusts..."

    $res = Invoke-Searcher `
           -Filter '(objectCategory=trustedDomain)' `
           -Props @('distinguishedName','trustPartner','trustType','trustDirection',
                    'trustAttributes','whenCreated','whenChanged',
                    'msDS-SupportedEncryptionTypes') `
           -SearchBase "CN=System,$Script:NC"

    $trusts = foreach ($r in $res) {
        $partner   = Get-Prop $r 'trustpartner'
        $type      = [int](Get-Prop $r 'trusttype')
        $direction = [int](Get-Prop $r 'trustdirection')
        $attrs     = [int](Get-Prop $r 'trustattributes')
        $created   = Convert-FileTime (Get-Prop $r 'whencreated')

        $typeStr = switch ($type) {
            1 { 'Downlevel (NT4)' } 2 { 'Uplevel (AD)' } 3 { 'MIT Kerberos' } 4 { 'DCE' } default { "Type$type" }
        }
        $dirStr = switch ($direction) {
            0 { 'Disabled' } 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' } default { "Dir$direction" }
        }

        $isForest    = ($attrs -band 8) -ne 0
        $isTransitive= ($attrs -band 1) -eq 0   # bit 0 = non-transitive when SET
        $isSIDFilter = ($attrs -band 4) -ne 0

        @{
            Partner    = $partner
            Type       = $typeStr
            Direction  = $dirStr
            IsForest   = $isForest
            Transitive = $isTransitive
            SIDFilter  = $isSIDFilter
            Created    = $created
            Attrs      = $attrs
        }
    }
    $Script:Trusts = $trusts

    # Bidirectional external trusts without SID filtering
    $risky = $trusts | Where-Object {
        $_.Direction -eq 'Bidirectional' -and -not $_.SIDFilter -and -not $_.IsForest
    }
    if ($risky.Count -gt 0) {
        Add-Finding -Category 'Trusts' -RuleId 'T-SIDFilter' `
            -Title "$($risky.Count) trust(s) without SID filtering (SIDHistory attack path)" `
            -Risk 'High' `
            -Detail "Trusts without SID filtering allow SIDHistory-based privilege escalation across the trust boundary." `
            -Remediation 'Enable SID filtering: netdom trust <TrustingDomain> /Domain:<TrustedDomain> /enablesidhistory:no' `
            -Data ($risky | ForEach-Object { $_.Partner })
    }

    # NT4 / downlevel trusts
    $nt4 = $trusts | Where-Object { $_.Type -match 'Downlevel' }
    if ($nt4.Count -gt 0) {
        Add-Finding -Category 'Trusts' -RuleId 'T-NT4Trust' `
            -Title "$($nt4.Count) NT4/downlevel trust(s) detected" `
            -Risk 'Medium' `
            -Detail 'NT4 trusts use weaker NTLM-based authentication and are a legacy security risk.' `
            -Remediation 'Migrate NT4 trusts to Active Directory trusts or remove if no longer needed.' `
            -Data ($nt4 | ForEach-Object { $_.Partner })
    }

    Write-OK "Trusts: $($trusts.Count) found"
}

#endregion

#region ── CHECK: ADCS / PKI ──────────────────────────────────────────────────

function Invoke-CheckPKI {
    Write-Status "Checking ADCS certificate templates..."

    $caRes = Invoke-Searcher `
             -Filter '(objectClass=pKIEnrollmentService)' `
             -Props @('name','dNSHostName','cACertificate','certificateTemplates','distinguishedName') `
             -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$Script:Config"

    if ($caRes.Count -eq 0) {
        Write-OK "No Certificate Authorities found in AD"
        return
    }
    Write-OK "Found $($caRes.Count) CA(s)"

    $tmplRes = Invoke-Searcher `
               -Filter '(objectClass=pKICertificateTemplate)' `
               -Props @('name','distinguishedName','msPKI-Certificate-Name-Flag',
                        'msPKI-Enrollment-Flag','msPKI-Private-Key-Flag',
                        'pKIExtendedKeyUsage','msPKI-Template-Schema-Version',
                        'nTSecurityDescriptor','whenChanged') `
               -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$Script:Config"

    $esc1  = [System.Collections.Generic.List[hashtable]]::new()
    $esc2  = [System.Collections.Generic.List[hashtable]]::new()
    $esc3  = [System.Collections.Generic.List[hashtable]]::new()

    # OID constants
    $clientAuthOID     = '1.3.6.1.5.5.7.3.2'
    $smartcardLogonOID = '1.3.6.1.4.1.311.20.2.2'
    $anyPurposeOID     = '2.5.29.37.0'
    $certReqAgentOID   = '1.3.6.1.4.1.311.20.2.1'

    foreach ($r in $tmplRes) {
        $name    = Get-Prop $r 'name'
        $nameFlag= [int](Get-Prop $r 'mspki-certificate-name-flag')
        $enrollF = [int](Get-Prop $r 'mspki-enrollment-flag')
        $ekus    = @($r.Properties['pkiextendedkeyusage'])

        $hasClientAuth = $ekus -contains $clientAuthOID -or
                         $ekus -contains $smartcardLogonOID -or
                         $ekus -contains $anyPurposeOID -or
                         $ekus.Count -eq 0

        # ESC1: Enrollee supplies subject + client auth EKU
        # msPKI-Certificate-Name-Flag bit 1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        if (($nameFlag -band 1) -ne 0 -and $hasClientAuth) {
            $esc1.Add(@{ Template=$name; NameFlag=$nameFlag; EKUs=($ekus -join ',') }) | Out-Null
        }

        # ESC2: Any Purpose or No EKU
        if ($ekus -contains $anyPurposeOID -or $ekus.Count -eq 0) {
            $esc2.Add(@{ Template=$name }) | Out-Null
        }

        # ESC3: Certificate Request Agent OID
        if ($ekus -contains $certReqAgentOID) {
            $esc3.Add(@{ Template=$name }) | Out-Null
        }
    }

    if ($esc1.Count -gt 0) {
        Add-Finding -Category 'Security' -RuleId 'S-ESC1' `
            -Title "ESC1: $($esc1.Count) template(s) allow enrollee-supplied SAN + client auth" `
            -Risk 'Critical' `
            -Detail 'An attacker who can enroll in these templates can request a certificate for any user (including Domain Admin) and authenticate as them.' `
            -Remediation 'Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag. Use CA-enforced subject from AD. Run Certify.exe find /vulnerable to confirm.' `
            -Data $esc1
    }

    if ($esc2.Count -gt 0) {
        Add-Finding -Category 'Security' -RuleId 'S-ESC2' `
            -Title "ESC2: $($esc2.Count) template(s) with Any Purpose or No EKU" `
            -Risk 'High' `
            -Detail 'Templates with Any Purpose EKU or no EKU can be used for any purpose including client authentication.' `
            -Remediation 'Replace Any Purpose EKU with specific, required EKUs only.' `
            -Data $esc2
    }

    if ($esc3.Count -gt 0) {
        Add-Finding -Category 'Security' -RuleId 'S-ESC3' `
            -Title "ESC3: $($esc3.Count) certificate request agent template(s)" `
            -Risk 'High' `
            -Detail 'Certificate Request Agent templates allow enrollment on behalf of other users, enabling impersonation chains.' `
            -Remediation 'Restrict enrollment on Certificate Request Agent templates to only authorized PKI administrators.' `
            -Data $esc3
    }

    Write-OK "PKI checks complete. ESC1:$($esc1.Count) ESC2:$($esc2.Count) ESC3:$($esc3.Count)"
}

#endregion

#region ── CHECK: Password & Security Settings ────────────────────────────────

function Invoke-CheckSecuritySettings {
    Write-Status "Checking directory security settings..."

    # dsHeuristics
    $dsRes = Invoke-Searcher `
             -Filter '(distinguishedName=CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=*)' `
             -Props @('dSHeuristics') `
             -SearchBase "CN=Directory Service,CN=Windows NT,CN=Services,$Script:Config" `
             -Scope 'Base'

    if ($dsRes.Count -gt 0) {
        $dsH = Get-Prop $dsRes[0] 'dsheuristics'
        if ($dsH) {
            $Script:DomainInfo['dsHeuristics'] = $dsH
            # Position 3 (0-indexed 2) = fAllowAnonNSPI - if '2' anonymous operations allowed
            if ($dsH.Length -ge 3 -and $dsH[2] -eq '2') {
                Add-Finding -Category 'Anomalies' -RuleId 'A-AnonNSPI' `
                    -Title 'dsHeuristics allows anonymous NSPI operations' `
                    -Risk 'High' `
                    -Detail "dsHeuristics bit 3 = '2' enables anonymous MAPI/NSPI access to the directory." `
                    -Remediation 'Set dsHeuristics bit 3 to 0 or 1 to disable anonymous NSPI.'
            }
            # Position 16 = AdminSDHolder SDProp interval (non-default = suspicious)
        }
    }

    # Fine-grained password policies
    $psoRes = Invoke-Searcher `
              -Filter '(objectClass=msDS-PasswordSettings)' `
              -Props @('name','msDS-MinimumPasswordLength','msDS-PasswordComplexityEnabled',
                       'msDS-LockoutThreshold','msDS-MaximumPasswordAge',
                       'msDS-PSOAppliesTo','distinguishedName') `
              -SearchBase "CN=Password Settings Container,CN=System,$Script:NC"

    $Script:PSOs = foreach ($r in $psoRes) {
        $minLen = [int](Get-Prop $r 'msds-minimumpasswordlength')
        $lockout= [int](Get-Prop $r 'msds-lockoutthreshold')
        @{
            Name    = Get-Prop $r 'name'
            MinLen  = $minLen
            Lockout = $lockout
            Complex = Get-Prop $r 'msds-passwordcomplexityenabled'
        }
    }

    # Unix passwords in AD
    $unixRes = Invoke-Searcher `
               -Filter '(&(objectCategory=person)(|(unixUserPassword=*)(userPassword=*)))' `
               -Props @('sAMAccountName','distinguishedName')

    if ($unixRes.Count -gt 0) {
        Add-Finding -Category 'Anomalies' -RuleId 'A-UnixPwd' `
            -Title "$($unixRes.Count) account(s) have Unix password attributes set" `
            -Risk 'High' `
            -Detail 'Attributes unixUserPassword/userPassword store cleartext or weakly-hashed passwords in AD, readable by any authenticated user.' `
            -Remediation 'Clear unixUserPassword and userPassword attributes. Use modern identity federation instead of LDAP simple bind.' `
            -Data @($unixRes | ForEach-Object { Get-Prop $_ 'samaccountname' })
    }

    # Java objects in AD (deserialization risk)
    $javaRes = Invoke-Searcher `
               -Filter '(&(objectCategory=person)(|(javacodebase=*)(javafactory=*)(javaclassname=*)(javaserializeddata=*)))' `
               -Props @('sAMAccountName','distinguishedName')

    if ($javaRes.Count -gt 0) {
        Add-Finding -Category 'Anomalies' -RuleId 'A-JavaObject' `
            -Title "$($javaRes.Count) AD object(s) contain Java serialization attributes" `
            -Risk 'Critical' `
            -Detail 'Java serialized objects stored in AD can trigger deserialization attacks when certain JNDI-enabled services query these accounts.' `
            -Remediation 'Remove Java attributes from all AD objects immediately. Audit LDAP-integrated Java application configurations.' `
            -Data @($javaRes | ForEach-Object { Get-Prop $_ 'samaccountname' })
    }

    # SID History on any object
    $sidRes = Invoke-Searcher `
              -Filter '(sIDHistory=*)' `
              -Props @('sAMAccountName','distinguishedName','objectClass')

    if ($sidRes.Count -gt 0) {
        $Script:DomainInfo['SIDHistoryCount'] = $sidRes.Count
    }

    Write-OK "Security settings checked"
}

#endregion

#region ── CHECK: FSMO Roles & AD Health ──────────────────────────────────────

function Invoke-CheckFSMO {
    Write-Status "Collecting FSMO roles..."

    try {
        $pdcRes = Invoke-Searcher `
                  -Filter '(&(objectClass=domainDNS)(fSMORoleOwner=*))' `
                  -Props @('fSMORoleOwner') -Scope 'Base'
        if ($pdcRes.Count -gt 0) {
            $Script:DomainInfo['PDC'] = Get-Prop $pdcRes[0] 'fsmoroleowner'
        }
    } catch {}

    Write-OK "FSMO collection complete"
}

#endregion


#region ── CHECK: Sensitive Privileged Groups ─────────────────────────────────

function Invoke-CheckSensitiveGroups {
    Write-Status "Checking sensitive privileged groups..."

    $builtinGroups = @(
        @{ SID='S-1-5-32-548'; Name='Account Operators';  Risk='High';
           Detail='Can create/modify most user and group objects in AD, including adding members to Domain Admins via nested groups.' }
        @{ SID='S-1-5-32-549'; Name='Server Operators';   Risk='High';
           Detail='Can interactively log on to DCs, start/stop services, and read/write DC filesystem — effective path to DC compromise.' }
        @{ SID='S-1-5-32-550'; Name='Print Operators';    Risk='High';
           Detail='Can load printer drivers on DCs (kernel mode code) — trivial DC compromise. PrintNightmare exploits this group.' }
        @{ SID='S-1-5-32-551'; Name='Backup Operators';   Risk='High';
           Detail='Can backup/restore any file regardless of permissions, including NTDS.dit — offline hash extraction path.' }
        @{ SID='S-1-5-32-552'; Name='Replicator';         Risk='Medium';
           Detail='Legacy replication group — should be empty in modern environments.' }
    )

    foreach ($grp in $builtinGroups) {
        $res = Invoke-Searcher -Filter "(objectSid=$($grp.SID))" `
               -Props @('member','name') -SearchBase "CN=Builtin,$Script:NC"
        if ($res.Count -gt 0) {
            $members = $res[0].Properties['member']
            if ($members -and $members.Count -gt 0) {
                Add-Finding -Category 'Accounts' `
                    -RuleId "P-$($grp.Name -replace ' ','')" `
                    -Title "$($grp.Name) has $($members.Count) member(s)" `
                    -Risk $grp.Risk `
                    -Detail $grp.Detail `
                    -Remediation "Remove all non-essential members from '$($grp.Name)'. Document each legitimate member with a business justification." `
                    -Data @($members)
            } else { Write-OK "$($grp.Name): empty (OK)" }
        }
    }

    # Enterprise Admins - should be empty outside forest-level operations
    $eaRes = Invoke-Searcher -Filter "(sAMAccountName=Enterprise Admins)" `
             -Props @('member') -SearchBase $Script:Forest
    if ($eaRes.Count -gt 0) {
        $eaM = @($eaRes[0].Properties['member'])
        if ($eaM.Count -gt 1) {
            Add-Finding -Category 'Accounts' -RuleId 'P-EnterpriseAdmins' `
                -Title "Enterprise Admins has $($eaM.Count) member(s) - should be minimal" `
                -Risk 'High' `
                -Detail 'Enterprise Admins grant forest-wide full control. Should contain only the built-in Administrator outside planned forest-level operations.' `
                -Remediation 'Remove all members except built-in Administrator when not performing forest-level operations.' `
                -Data @($eaM)
        } else { Write-OK "Enterprise Admins: minimal membership (OK)" }
    }

    # Domain Admins NOT in Protected Users (Protected Users blocks NTLM, RC4, delegation)
    $daRes = Invoke-Searcher -Filter "(sAMAccountName=Domain Admins)"  -Props @('member')
    $puRes = Invoke-Searcher -Filter "(sAMAccountName=Protected Users)" -Props @('member')
    if ($daRes.Count -gt 0 -and $puRes.Count -gt 0) {
        $daM = @($daRes[0].Properties['member'])
        $puM = @($puRes[0].Properties['member'])
        $notProtected = $daM | Where-Object { $puM -notcontains $_ -and $_ -notmatch 'CN=krbtgt' }
        if ($notProtected.Count -gt 0) {
            Add-Finding -Category 'Accounts' -RuleId 'P-ProtectedUsers' `
                -Title "$($notProtected.Count) Domain Admin(s) not in Protected Users group" `
                -Risk 'Medium' `
                -Detail 'Protected Users prevents NTLM authentication, DES/RC4 Kerberos, and unconstrained delegation. All DA accounts should be enrolled.' `
                -Remediation 'Add Domain Admin accounts to Protected Users security group. Test application compatibility before enforcing.' `
                -Data @($notProtected | Select-Object -First 10)
        } else { Write-OK "Protected Users: all Domain Admins enrolled (OK)" }
    }

    Write-OK "Sensitive group checks complete"
}

#endregion

#region ── CHECK: Built-in Accounts and Weak Account Flags ────────────────────

function Invoke-CheckBuiltinAccounts {
    Write-Status "Checking built-in accounts and weak UAC flags..."

    # Guest account enabled
    $gRes = Invoke-Searcher -Filter "(sAMAccountName=Guest)" -Props @('userAccountControl')
    if ($gRes.Count -gt 0 -and -not (Test-UAC ([int](Get-Prop $gRes[0] 'useraccountcontrol')) 0x2)) {
        Add-Finding -Category 'Anomalies' -RuleId 'A-GuestEnabled' `
            -Title 'Guest account is enabled' -Risk 'High' `
            -Detail 'The built-in Guest account is active, allowing unauthenticated or anonymous access.' `
            -Remediation 'Disable-ADAccount -Identity Guest'
    } else { Write-OK "Guest account: disabled (OK)" }

    # Built-in Administrator - renamed? password age?
    $adminSID = "$($Script:DomainInfo['SID'])-500"
    $aRes = Invoke-Searcher -Filter "(objectSid=$adminSID)" `
            -Props @('sAMAccountName','pwdLastSet','lastLogonTimestamp')
    if ($aRes.Count -gt 0) {
        $sam    = Get-Prop $aRes[0] 'samaccountname'
        $pwdSet = Convert-FileTime (Get-Prop $aRes[0] 'pwdlastset')
        if ($sam -eq 'Administrator') {
            Add-Finding -Category 'Anomalies' -RuleId 'A-AdminNotRenamed' `
                -Title 'Built-in Administrator account has not been renamed' -Risk 'Low' `
                -Detail 'Predictable account name makes brute-force and credential stuffing easier.' `
                -Remediation 'Rename via GPO restricted groups or manually in ADUC.'
        }
        if ($pwdSet -and (Days-Ago $pwdSet) -gt 365) {
            Add-Finding -Category 'Anomalies' -RuleId 'A-AdminPwdAge' `
                -Title "Built-in Administrator password is $((Days-Ago $pwdSet)) days old" -Risk 'High' `
                -Detail 'A stale Administrator password is a priority pass-the-hash and brute-force target.' `
                -Remediation 'Rotate the Administrator password. Deploy LAPS for workstation local admin accounts.'
        }
    }

    # PASSWD_NOTREQD (UAC bit 0x20) - blank password allowed
    $pnrRes = Invoke-Searcher `
              -Filter "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
              -Props @('sAMAccountName','distinguishedName')
    if ($pnrRes.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-PasswordNotRequired' `
            -Title "$($pnrRes.Count) enabled account(s) with PASSWD_NOTREQD (blank password allowed)" `
            -Risk 'High' `
            -Detail 'PASSWD_NOTREQD bypasses the domain password policy, allowing empty passwords.' `
            -Remediation 'Set-ADUser -PasswordNotRequired $false for all affected accounts. Set strong passwords.' `
            -Data @($pnrRes | ForEach-Object { Get-Prop $_ 'samaccountname' })
    }

    # Reversible encryption (UAC bit 0x80)
    $revRes = Invoke-Searcher `
              -Filter "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=128)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
              -Props @('sAMAccountName','distinguishedName')
    if ($revRes.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-ReversibleEncryption' `
            -Title "$($revRes.Count) account(s) store passwords with reversible encryption (cleartext)" `
            -Risk 'Critical' `
            -Detail 'Reversible encryption stores passwords in recoverable form in NTDS.dit. Any DCSync or NTDS.dit extraction yields plaintext passwords for these accounts.' `
            -Remediation 'Disable reversible encryption. Only legacy CHAP authentication requires it. Migrate those apps.' `
            -Data @($revRes | ForEach-Object { Get-Prop $_ 'samaccountname' })
    }

    # DES-only Kerberos (UAC bit 0x200000)
    $desRes = Invoke-Searcher `
              -Filter "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2097152)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
              -Props @('sAMAccountName','distinguishedName')
    if ($desRes.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-DESOnly' `
            -Title "$($desRes.Count) account(s) restricted to DES-only Kerberos encryption" `
            -Risk 'High' `
            -Detail 'DES is a 56-bit broken cipher. DES Kerberos tickets crack in minutes. High-priority Kerberoasting targets.' `
            -Remediation 'Remove USE_DES_KEY_ONLY flag. Migrate applications to AES-128/256 Kerberos.' `
            -Data @($desRes | ForEach-Object { Get-Prop $_ 'samaccountname' })
    }

    # Privileged accounts with non-expiring passwords
    $privNoExp = Invoke-Searcher `
                 -Filter "(&(objectCategory=person)(adminCount=1)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=krbtgt)))" `
                 -Props @('sAMAccountName','distinguishedName')
    if ($privNoExp.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-PrivNoExpiry' `
            -Title "$($privNoExp.Count) privileged account(s) with non-expiring passwords" `
            -Risk 'High' `
            -Detail 'Privileged accounts (adminCount=1) with passwords that never expire accumulate risk over time. A compromised credential stays valid indefinitely.' `
            -Remediation 'Remove DONT_EXPIRE_PASSWD from privileged accounts. Use PSO to enforce 90-day rotation for admins.' `
            -Data @($privNoExp | ForEach-Object { Get-Prop $_ 'samaccountname' })
    }

    Write-OK "Built-in account and UAC flag checks complete"
}

#endregion

#region ── CHECK: GPP Passwords in SYSVOL ─────────────────────────────────────

function Invoke-CheckGPPPasswords {
    Write-Status "Scanning SYSVOL for GPP cpassword entries..."

    $sysvolPath = "\\$Script:BindServer\SYSVOL\$Domain\Policies"
    if (-not (Test-Path $sysvolPath -ErrorAction SilentlyContinue)) {
        Write-Status "SYSVOL not accessible from this host - skipping GPP scan" 'Yellow'
        return
    }

    $gpFiles = Get-ChildItem -Path $sysvolPath -Recurse -ErrorAction SilentlyContinue `
               -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'

    $gppFinds = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($file in $gpFiles) {
        try {
            [xml]$xml = Get-Content $file.FullName -ErrorAction Stop
            foreach ($node in $xml.SelectNodes("//*[@cpassword]")) {
                $cp = $node.GetAttribute('cpassword')
                if (-not [string]::IsNullOrEmpty($cp)) {
                    $user = $node.GetAttribute('userName')
                    if (-not $user) { $user = $node.GetAttribute('name') }
                    $gppFinds.Add(@{
                        File = ($file.FullName -replace [regex]::Escape($sysvolPath),'')
                        User = $user
                        Hint = $cp.Substring(0,[Math]::Min(24,$cp.Length)) + '...'
                    }) | Out-Null
                }
            }
        } catch {}
    }

    if ($gppFinds.Count -gt 0) {
        Add-Finding -Category 'Security' -RuleId 'S-GPPPassword' `
            -Title "GPP Passwords (cpassword) found in SYSVOL - $($gppFinds.Count) occurrence(s)" `
            -Risk 'Critical' `
            -Detail 'Group Policy Preferences passwords are encrypted with a Microsoft-published AES key (MS14-025). Any domain user can decrypt them to recover plaintext credentials. This 10+ year old issue is trivially exploited by any attacker with domain user rights.' `
            -Remediation '1) Delete all cpassword entries from SYSVOL XML files immediately. 2) Rotate all exposed credentials. 3) Deploy LAPS instead. 4) Apply MS14-025.' `
            -Data $gppFinds
    } else {
        Write-OK "GPP Passwords: none found in SYSVOL (OK)"
    }
}

#endregion

#region ── CHECK: Kerberos Encryption Types ───────────────────────────────────

function Invoke-CheckKerberosEncryption {
    Write-Status "Checking Kerberos encryption types on DCs and service accounts..."

    # msDS-SupportedEncryptionTypes bits: 0x1=DES-CRC 0x2=DES-MD5 0x4=RC4 0x8=AES128 0x10=AES256
    $desDCs  = [System.Collections.Generic.List[hashtable]]::new()
    $rc4DCs  = [System.Collections.Generic.List[hashtable]]::new()
    $noAESDCs= [System.Collections.Generic.List[hashtable]]::new()

    foreach ($dc in $Script:DCList) {
        $r = Invoke-Searcher -Filter "(sAMAccountName=$($dc.Name)`$)" `
             -Props @('msDS-SupportedEncryptionTypes')
        if ($r.Count -eq 0) { continue }
        $enc = [int](Get-Prop $r[0] 'msds-supportedencryptiontypes')
        if ($enc -eq 0) { $enc = 0x1C }

        if (($enc -band 0x3)  -ne 0) { $desDCs.Add(@{Name=$dc.Name;Enc=$enc})  | Out-Null }
        if (($enc -band 0x4)  -ne 0) { $rc4DCs.Add(@{Name=$dc.Name;Enc=$enc})  | Out-Null }
        if (($enc -band 0x18) -eq 0) { $noAESDCs.Add(@{Name=$dc.Name;Enc=$enc}) | Out-Null }
    }

    if ($desDCs.Count -gt 0) {
        Add-Finding -Category 'Security' -RuleId 'S-DES-DC' `
            -Title "DES Kerberos encryption supported on $($desDCs.Count) DC(s)" `
            -Risk 'Critical' `
            -Detail 'DES (56-bit) is cryptographically broken. DES Kerberos tickets crack offline in minutes with modern hardware.' `
            -Remediation 'Disable DES in GPO: Computer Config > Windows Settings > Security Options > "Network security: Configure encryption types allowed for Kerberos" - uncheck all DES options.' `
            -Data $desDCs
    }

    if ($rc4DCs.Count -gt 0) {
        Add-Finding -Category 'Security' -RuleId 'S-RC4-DC' `
            -Title "RC4 Kerberos still enabled on $($rc4DCs.Count) DC(s)" `
            -Risk 'Medium' `
            -Detail 'RC4 enables faster offline Kerberoasting and AS-REP Roasting. AES-only Kerberos is the modern standard (required by Windows 11/Server 2025 defaults).' `
            -Remediation 'Disable RC4 in GPO Kerberos encryption policy after verifying no legacy application requires it. Test thoroughly before enforcing.' `
            -Data $rc4DCs
    }

    if ($noAESDCs.Count -gt 0) {
        Add-Finding -Category 'Security' -RuleId 'S-NoAES-DC' `
            -Title "$($noAESDCs.Count) DC(s) not supporting AES Kerberos" -Risk 'High' `
            -Detail 'DCs without AES support force all Kerberos auth to weaker RC4/DES algorithms.' `
            -Remediation 'Upgrade DC OS to Windows Server 2008+. Enable AES in msDS-SupportedEncryptionTypes (set to 24 for AES128+AES256).' `
            -Data $noAESDCs
    }

    # Service accounts restricted to RC4 only (no AES keys)
    $rc4SvcRes = Invoke-Searcher `
                 -Filter "(&(objectCategory=person)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=4)(!(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=8)))" `
                 -Props @('sAMAccountName','distinguishedName')
    if ($rc4SvcRes.Count -gt 0) {
        Add-Finding -Category 'Security' -RuleId 'S-RC4ServiceAcct' `
            -Title "$($rc4SvcRes.Count) Kerberoastable service account(s) RC4-only (priority cracking targets)" `
            -Risk 'Medium' `
            -Detail 'RC4 Kerberos tickets crack ~10x faster than AES in offline attacks. Service accounts with SPN and RC4-only keys are highest-priority Kerberoasting targets.' `
            -Remediation 'Force interactive login or password reset on these accounts to generate AES keys. Set msDS-SupportedEncryptionTypes = 24.' `
            -Data @($rc4SvcRes | ForEach-Object { Get-Prop $_ 'samaccountname' })
    }

    Write-OK "Kerberos encryption: DES DCs=$($desDCs.Count) RC4 DCs=$($rc4DCs.Count)"
}

#endregion

#region ── CHECK: GPO Security Settings ───────────────────────────────────────

function Invoke-CheckGPOSecurity {
    Write-Status "Analysing GPO security settings in SYSVOL..."

    $sysvolPath = "\\$Script:BindServer\SYSVOL\$Domain\Policies"
    if (-not (Test-Path $sysvolPath -ErrorAction SilentlyContinue)) {
        Write-Status "SYSVOL not accessible - skipping GPO security analysis" 'Yellow'
        return
    }

    $g = @{ WDigest=$false; LMLevel=99; SMBSigning=$false; LDAPSigning=$false
            PSLogging=$false; PointPrint=$false }

    foreach ($inf in (Get-ChildItem $sysvolPath -Recurse -Include 'GptTmpl.inf' -EA SilentlyContinue)) {
        $c = Get-Content $inf.FullName -EA SilentlyContinue
        if (-not $c) { continue }
        if ($c -match 'LmCompatibilityLevel\s*=\s*(\d+)') {
            $lvl = [int]$Matches[1]; if ($lvl -lt $g.LMLevel) { $g.LMLevel = $lvl }
        }
        if ($c -match 'RequireSecuritySignature\s*=\s*1') { $g.SMBSigning  = $true }
        if ($c -match 'LDAPServerIntegrity\s*=\s*2')      { $g.LDAPSigning = $true }
    }

    foreach ($xml in (Get-ChildItem $sysvolPath -Recurse -Include 'Registry.xml' -EA SilentlyContinue)) {
        try {
            [xml]$x = Get-Content $xml.FullName -EA Stop
            foreach ($item in $x.SelectNodes("//Registry/Properties")) {
                $key = $item.key; $name = $item.name; $val = $item.value
                if ($key -match 'WDigest'            -and $name -eq 'UseLogonCredential'           -and $val -eq '1') { $g.WDigest   = $true }
                if ($key -match 'ScriptBlockLogging' -and $name -eq 'EnableScriptBlockLogging'     -and $val -eq '1') { $g.PSLogging = $true }
                if ($key -match 'Point and Print'    -and $name -eq 'NoWarningNoElevationOnInstall' -and $val -eq '0') { $g.PointPrint= $true }
            }
        } catch {}
    }

    if ($g.WDigest) {
        Add-Finding -Category 'Security' -RuleId 'S-WDigest' `
            -Title 'WDigest authentication ENABLED via GPO - plaintext passwords in LSASS' `
            -Risk 'Critical' `
            -Detail 'WDigest causes Windows to cache plaintext credentials in LSASS memory. Mimikatz sekurlsa::wdigest extracts them without admin rights. This GPO undoes Credential Guard protection.' `
            -Remediation 'Set HKLM\...\WDigest\UseLogonCredential = 0 via GPO. Deploy Windows Defender Credential Guard.'
    }

    if ($g.LMLevel -lt 99 -and $g.LMLevel -lt 3) {
        Add-Finding -Category 'Security' -RuleId 'S-LMLevel' `
            -Title "Weak NTLM level in GPO: LmCompatibilityLevel = $($g.LMLevel)" `
            -Risk 'High' `
            -Detail "Level $($g.LMLevel) allows LM/NTLMv1 - hashes crackable in seconds. Level 5 (NTLMv2 only) is minimum recommended." `
            -Remediation 'Set LmCompatibilityLevel = 5 via GPO Security Options: "Send NTLMv2 response only, refuse LM and NTLM".'
    }

    if (-not $g.SMBSigning) {
        Add-Finding -Category 'Security' -RuleId 'S-SMBSigning' `
            -Title 'SMB signing not enforced in GPO' -Risk 'High' `
            -Detail 'Without mandatory SMB signing, NTLM relay attacks (Responder + ntlmrelayx) let attackers impersonate domain users to SMB services.' `
            -Remediation 'Enable "Microsoft network server: Digitally sign communications (always)" AND the equivalent client policy via GPO. Required for all DCs at minimum.'
    }

    if (-not $g.LDAPSigning) {
        Add-Finding -Category 'Security' -RuleId 'S-LDAPSigning' `
            -Title 'LDAP server signing not required in GPO' -Risk 'High' `
            -Detail 'Without LDAP signing, LDAP relay enables AD object creation (noPac, RBCD attacks). Combined with PetitPotam this is a common domain takeover chain.' `
            -Remediation 'GPO: "Domain controller: LDAP server signing requirements = Require signing". Also enable LDAP channel binding (KB4520412).'
    }

    if ($g.PointPrint) {
        Add-Finding -Category 'Security' -RuleId 'S-PointPrint' `
            -Title 'Point and Print restrictions disabled (PrintNightmare vector)' `
            -Risk 'Critical' `
            -Detail 'NoWarningNoElevationOnInstall = 0 disables elevation prompt for unsigned printer drivers. Directly enables PrintNightmare (CVE-2021-34527) exploitation for SYSTEM on any affected host.' `
            -Remediation 'Set NoWarningNoElevationOnInstall = 1 and UpdatePromptSettings = 2. Apply CVE-2021-34527 patches. Disable Print Spooler on all DCs.'
    }

    if (-not $g.PSLogging) {
        Add-Finding -Category 'Anomalies' -RuleId 'A-PSLogging' `
            -Title 'PowerShell Script Block Logging not enabled in GPO' -Risk 'Low' `
            -Detail 'Without Script Block Logging, PowerShell-based attacks (Empire, Cobalt Strike, living-off-the-land) leave no forensic evidence in event logs.' `
            -Remediation 'GPO: Computer Config > Admin Templates > Windows Components > PowerShell: Enable Script Block Logging and Module Logging.'
    }

    Write-OK "GPO security settings analysed"
}

#endregion

#region ── CHECK: Exchange AD Permissions ─────────────────────────────────────

function Invoke-CheckExchangePermissions {
    Write-Status "Checking Exchange AD permissions (PrivExchange path)..."

    $ewpRes = Invoke-Searcher -Filter "(sAMAccountName=Exchange Windows Permissions)" `
              -Props @('member','distinguishedName')
    if ($ewpRes.Count -gt 0) {
        $m = @($ewpRes[0].Properties['member'])
        if ($m.Count -gt 0) {
            Add-Finding -Category 'Security' -RuleId 'S-ExchangeWriteDACL' `
                -Title "Exchange Windows Permissions group has $($m.Count) member(s) - PrivExchange DCSync path" `
                -Risk 'Critical' `
                -Detail 'This group has WriteDACL on the domain NC. Any member can grant themselves DS-Replication-Get-Changes-All and perform DCSync to dump all password hashes. This is the PrivExchange attack (CVE-2019-0686 / PrivExchange.py).' `
                -Remediation 'Apply PrivExchange mitigation to remove excessive WriteDACL from Exchange groups on the domain root. See: https://github.com/gdedrouas/Exchange-AD-Privesc' `
                -Data @($m | Select-Object -First 10)
        }
    }

    $etsRes = Invoke-Searcher -Filter "(sAMAccountName=Exchange Trusted Subsystem)" `
              -Props @('member','distinguishedName')
    if ($etsRes.Count -gt 0) {
        $m = @($etsRes[0].Properties['member'])
        if ($m.Count -gt 0) {
            Add-Finding -Category 'Security' -RuleId 'S-ExchangeTrustedSubsystem' `
                -Title "Exchange Trusted Subsystem has $($m.Count) member(s) (Exchange machine accounts)" `
                -Risk 'High' `
                -Detail 'Exchange Trusted Subsystem has GenericAll on many AD objects. Compromise of any Exchange server is effectively a domain admin equivalent.' `
                -Remediation 'Keep Exchange servers patched and treated as Tier-0. Apply PrivExchange mitigation script.'
        }
    }

    Write-OK "Exchange permission checks complete"
}

#endregion

#region ── CHECK: ADCS Extended ESC4 / ESC6 / ESC8 ───────────────────────────

function Invoke-CheckADCSExtended {
    Write-Status "Checking ADCS extended misconfigs (ESC4/6/8)..."

    $caRes = Invoke-Searcher -Filter '(objectClass=pKIEnrollmentService)' `
             -Props @('name','dNSHostName','flags','distinguishedName') `
             -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$Script:Config"
    if ($caRes.Count -eq 0) { Write-OK "No CAs found - skipping ADCS extended"; return }

    foreach ($ca in $caRes) {
        $caName = Get-Prop $ca 'name'
        $caHost = Get-Prop $ca 'dnshostname'
        $flags  = [int](Get-Prop $ca 'flags')

        # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag
        if (($flags -band 0x00040000) -ne 0) {
            Add-Finding -Category 'Security' -RuleId 'S-ESC6' `
                -Title "ESC6: CA '$caName' has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled" `
                -Risk 'Critical' `
                -Detail 'This CA flag allows users to include arbitrary SANs in ALL certificate requests, making every enrollable template an ESC1 equivalent. Any domain user can request a certificate for Domain Admin.' `
                -Remediation "Disable: certutil -config ""$caHost\$caName"" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 then restart CertSvc."
        }

        # ESC8: HTTP web enrollment (NTLM relay target for PetitPotam chain)
        if (-not [string]::IsNullOrEmpty($caHost)) {
            try {
                $req = [System.Net.WebRequest]::Create("http://$caHost/certsrv/")
                $req.Timeout = 3000; $req.Method = 'HEAD'; $req.AllowAutoRedirect = $false
                $resp = $req.GetResponse(); $sc = [int]$resp.StatusCode; $resp.Close()
                if ($sc -lt 400) {
                    Add-Finding -Category 'Security' -RuleId 'S-ESC8' `
                        -Title "ESC8: HTTP web enrollment accessible on CA '$caName' ($caHost)" `
                        -Risk 'Critical' `
                        -Detail 'HTTP ADCS web enrollment accepts NTLM. PetitPotam forces DC to authenticate to this endpoint, then relay yields a DC certificate. Use it to forge Kerberos tickets (UnPAC-the-Hash / Golden Certificate).' `
                        -Remediation 'Disable HTTP enrollment. Enforce HTTPS. Enable Extended Protection for Authentication (EPA) on IIS. Disable NTLM on the enrollment endpoint.'
                }
            } catch {}
        }
    }

    Write-OK "ADCS extended checks complete"
}

#endregion

#region ── CHECK: RODC Password Replication Policy ────────────────────────────

function Invoke-CheckRODC {
    Write-Status "Checking RODC password replication policies..."

    $rodcs = @($Script:DCList | Where-Object { $_.IsRODC })
    if ($rodcs.Count -eq 0) { Write-OK "No RODCs found"; return }

    foreach ($rodc in $rodcs) {
        $r = Invoke-Searcher -Filter "(sAMAccountName=$($rodc.Name)`$)" `
             -Props @('msDS-RevealOnDemandGroup','msDS-NeverRevealGroup','msDS-RevealedUsers')
        if ($r.Count -eq 0) { continue }

        $allowed  = @($r[0].Properties['msds-revealondemandgroup'])
        $revealed = @($r[0].Properties['msds-revealedusers'])

        $dangerousAllowed = $allowed | Where-Object { $_ -match 'Domain Admins|Enterprise Admins|CN=Administrators|Schema Admins' }
        if ($dangerousAllowed.Count -gt 0) {
            Add-Finding -Category 'Security' -RuleId 'S-RODCPrivReplication' `
                -Title "RODC $($rodc.Name): privileged accounts in Allowed Password Replication" `
                -Risk 'Critical' `
                -Detail 'If this RODC is compromised (physical or logical), all accounts in the Allowed Replication Group are compromised. Tier-0 credentials must never be cached on RODCs.' `
                -Remediation 'Remove Domain Admins and all Tier-0 accounts from the RODC Allowed Password Replication Group immediately.' `
                -Data @($dangerousAllowed)
        }

        if ($revealed.Count -gt 20) {
            Add-Finding -Category 'Security' -RuleId 'S-RODCManyRevealed' `
                -Title "RODC $($rodc.Name) has $($revealed.Count) cached credential sets" `
                -Risk 'Medium' `
                -Detail 'A large number of cached credentials increases the blast radius if this RODC is compromised.' `
                -Remediation 'Review the msDS-RevealedUsers list. Reset passwords for accounts no longer requiring RODC caching.'
        }
    }

    Write-OK "RODC checks complete ($($rodcs.Count) RODC(s))"
}

#endregion

#region ── CHECK: Shadow Credentials ─────────────────────────────────────────

function Invoke-CheckShadowCredentials {
    Write-Status "Checking for Shadow Credential entries (msDS-KeyCredentialLink)..."

    $res = Invoke-Searcher `
           -Filter "(&(msDS-KeyCredentialLink=*)(!(primaryGroupID=516))(!(primaryGroupID=521))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
           -Props @('sAMAccountName','distinguishedName','msDS-KeyCredentialLink')

    if ($res.Count -gt 0) {
        $sc = foreach ($r in $res) {
            @{ Sam=(Get-Prop $r 'samaccountname'); DN=(Get-Prop $r 'distinguishedname')
               Keys=$r.Properties['msds-keycredentiallink'].Count }
        }
        Add-Finding -Category 'Security' -RuleId 'S-ShadowCreds' `
            -Title "$($sc.Count) non-DC account(s) have msDS-KeyCredentialLink entries" `
            -Risk 'High' `
            -Detail 'msDS-KeyCredentialLink enables passwordless PKINIT auth. Whisker/PyWhisker add entries to silently hijack accounts without changing passwords (no lockout, minimal logging). Unexpected entries indicate persistence or active compromise.' `
            -Remediation 'Audit all msDS-KeyCredentialLink entries. Remove unauthorized ones. Monitor Event ID 5136 for changes to this attribute on privileged accounts.' `
            -Data $sc
    } else {
        Write-OK "Shadow credentials: no unexpected entries found"
    }
}

#endregion

#region ── CHECK: Azure AD Connect and Entra ID ───────────────────────────────

function Invoke-CheckAzureADConnect {
    Write-Status "Checking Azure AD Connect / Entra ID configuration..."

    # AZUREADSSOACC$ - Seamless SSO Kerberos key rotation
    $ssoRes = Invoke-Searcher -Filter '(sAMAccountName=AZUREADSSOACC$)' `
              -Props @('pwdLastSet','distinguishedName')
    if ($ssoRes.Count -gt 0) {
        $pwdSet = Convert-FileTime (Get-Prop $ssoRes[0] 'pwdlastset')
        $age    = if ($pwdSet) { Days-Ago $pwdSet } else { 9999 }
        if ($age -gt 180) {
            Add-Finding -Category 'Security' -RuleId 'S-AzureSSOAge' `
                -Title "AZUREADSSOACC`$ Kerberos key not rotated in $age days (Microsoft recommends 30)" `
                -Risk 'High' `
                -Detail 'This account holds the Kerberos decryption key for Entra ID Seamless SSO. If NTDS.dit is extracted, this key can forge Silver Tickets for any Entra ID user without a certificate.' `
                -Remediation 'Rotate via AAD Connect PowerShell: Update-AzureADSSOForest -OnPremCredentials $creds. Verify account is in NeverReveal list on all RODCs.'
        } else { Write-OK "AZUREADSSOACC`$ key age: $age days (OK)" }
    }

    # MSOL_* sync accounts - typically have DCSync-level rights
    $msolRes = Invoke-Searcher -Filter "(sAMAccountName=MSOL_*)" `
               -Props @('sAMAccountName','distinguishedName','pwdLastSet')
    if ($msolRes.Count -gt 0) {
        $msol = foreach ($r in $msolRes) {
            @{ Sam=(Get-Prop $r 'samaccountname'); DN=(Get-Prop $r 'distinguishedname')
               PwdAge=if($p=Convert-FileTime(Get-Prop $r 'pwdlastset')){Days-Ago $p}else{9999} }
        }
        Add-Finding -Category 'Security' -RuleId 'S-MSOLAccount' `
            -Title "$($msol.Count) Azure AD Connect sync account(s) (MSOL_*) detected" `
            -Risk 'High' `
            -Detail 'MSOL_* accounts are granted DS-Replication-Get-Changes-All by AAD Connect setup. Compromise of the sync server = full domain DCSync. The AAD Connect server must be treated as Tier-0.' `
            -Remediation 'Treat AAD Connect server as Tier-0. Restrict network access. Rotate MSOL account passwords. Follow AAD Connect hardening guide.' `
            -Data $msol
    }

    Write-OK "Azure AD / Entra ID checks complete"
}

#endregion

#region ── CHECK: DNS Security ────────────────────────────────────────────────

function Invoke-CheckDNSSecurity {
    Write-Status "Checking DNS security configuration..."

    # WPAD DNS record
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses("wpad.$Domain")
        if ($resolved.Count -gt 0) {
            Add-Finding -Category 'Anomalies' -RuleId 'A-WPAD' `
                -Title "WPAD DNS record exists: wpad.$Domain -> $($resolved[0])" `
                -Risk 'High' `
                -Detail 'A WPAD record lets an attacker serve a malicious PAC file to all domain clients using proxy auto-discovery, silently proxying HTTP traffic for NTLM credential capture.' `
                -Remediation 'Remove the WPAD DNS record. Add "wpad" to the DNS Global Query Block List. Disable "Automatically detect proxy settings" via GPO.'
        }
    } catch {}

    # Wildcard DNS records
    try {
        $wcRes = Invoke-Searcher -Filter "(name=\2A)" `
                 -Props @('name','distinguishedName') `
                 -SearchBase "DC=$($Domain -replace '\.',',DC='),DC=DomainDnsZones,$Script:NC" `
                 -Scope 'OneLevel'
        if ($wcRes.Count -gt 0) {
            Add-Finding -Category 'Anomalies' -RuleId 'A-DNSWildcard' `
                -Title "$($wcRes.Count) DNS wildcard record(s) found in domain zone" `
                -Risk 'Medium' `
                -Detail 'Wildcard DNS (*) records resolve any unknown hostname, enabling passive NTLM capture without network poisoning (no LLMNR/NBT-NS required).' `
                -Remediation 'Remove wildcard DNS records unless required for a documented service. Audit the DNS zone for unexpected entries.'
        }
    } catch {}

    # DNSAdmins group (DLL injection to SYSTEM on DCs)
    $dnsAdmRes = Invoke-Searcher -Filter "(sAMAccountName=DNSAdmins)" -Props @('member')
    if ($dnsAdmRes.Count -gt 0) {
        $dnsM = @($dnsAdmRes[0].Properties['member'])
        if ($dnsM.Count -gt 0) {
            Add-Finding -Category 'Security' -RuleId 'S-DNSAdmins' `
                -Title "DNSAdmins group has $($dnsM.Count) member(s) - DLL injection path to SYSTEM on DCs" `
                -Risk 'High' `
                -Detail 'DNSAdmins members can load arbitrary DLLs into the DNS service (running as SYSTEM on DCs) via dnscmd /config /serverlevelplugindll. This is a reliable DC privilege escalation path.' `
                -Remediation 'Remove all non-essential DNSAdmins members. Treat DNSAdmins as Tier-0. Monitor dnscmd.exe usage via process creation logging.' `
                -Data @($dnsM | Select-Object -First 10)
        }
    }

    Write-OK "DNS security checks complete"
}

#endregion

#region ── CHECK: LAPS Schema and ACL ────────────────────────────────────────

function Invoke-CheckLAPSACL {
    Write-Status "Checking LAPS schema presence and ACL security..."

    $legacyLAPS = Invoke-Searcher -Filter "(lDAPDisplayName=ms-Mcs-AdmPwd)"  -Props @('distinguishedName') -SearchBase $Script:Schema
    $newLAPS    = Invoke-Searcher -Filter "(lDAPDisplayName=msLAPS-Password)" -Props @('distinguishedName') -SearchBase $Script:Schema

    if ($legacyLAPS.Count -eq 0 -and $newLAPS.Count -eq 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-LAPSNotInstalled' `
            -Title 'LAPS schema not present - local admin passwords are likely static and shared' `
            -Risk 'High' `
            -Detail 'Without LAPS, local Administrator passwords are set once during imaging and never rotated. Pass-the-hash lateral movement across identically imaged machines is trivial.' `
            -Remediation 'Deploy Windows LAPS (built-in since Windows Server 2019 / Win10 2004+). For legacy systems use the LAPS MSI from Microsoft.'
        return
    }

    $lapsType = @()
    if ($legacyLAPS.Count -gt 0) { $lapsType += 'Legacy (ms-Mcs-AdmPwd)' }
    if ($newLAPS.Count    -gt 0) { $lapsType += 'Windows LAPS (msLAPS-Password)' }
    Write-OK "LAPS schema present: $($lapsType -join ', ')"

    # Check for overly broad read access on LAPS attribute (requires AD: drive)
    if ($legacyLAPS.Count -gt 0) {
        try {
            $acl = Get-Acl "AD:\$($legacyLAPS[0].Properties['distinguishedname'][0])" -EA Stop
            $broad = $acl.Access | Where-Object {
                $_.ActiveDirectoryRights -match 'ReadProperty|GenericAll|GenericRead' -and
                $_.IdentityReference -match 'Authenticated Users|Everyone|Domain Users|Domain Computers'
            }
            if ($broad) {
                Add-Finding -Category 'Security' -RuleId 'S-LAPSOpenRead' `
                    -Title 'LAPS password attribute readable by broad groups (all domain users)' `
                    -Risk 'High' `
                    -Detail 'The ms-Mcs-AdmPwd attribute is readable by Authenticated Users or similar groups, exposing ALL local admin passwords to every domain user.' `
                    -Remediation 'Remove read access from broad groups on ms-Mcs-AdmPwd. Delegate read access only to specific helpdesk/admin security groups per OU.'
            }
        } catch {}
    }
}

#endregion

#region ── CHECK: Display Specifiers Backdoor ─────────────────────────────────

function Invoke-CheckDisplaySpecifiers {
    Write-Status "Checking Display Specifiers for backdoor entries..."

    $res = Invoke-Searcher -Filter "(adminContextMenu=*)" `
           -Props @('name','adminContextMenu','whenChanged') `
           -SearchBase "CN=DisplaySpecifiers,$Script:Config"

    $suspects = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($r in $res) {
        foreach ($entry in $r.Properties['admincontextmenu']) {
            if ($entry -match '\\\\'  -or
                $entry -match '\.exe' -or $entry -match '\.vbs' -or
                $entry -match '\.ps1' -or $entry -match '\.bat' -or
                $entry -match '\.hta' -or $entry -match 'http') {
                if ($entry -notmatch '%systemroot%|%windir%') {
                    $suspects.Add(@{
                        Specifier   = Get-Prop $r 'name'
                        Entry       = "$entry"
                        WhenChanged = Convert-FileTime (Get-Prop $r 'whenchanged')
                    }) | Out-Null
                }
            }
        }
    }

    if ($suspects.Count -gt 0) {
        Add-Finding -Category 'Anomalies' -RuleId 'A-DisplaySpecifier' `
            -Title "$($suspects.Count) Display Specifier(s) with suspicious adminContextMenu entries" `
            -Risk 'Critical' `
            -Detail 'Tampered Display Specifier adminContextMenu entries silently execute arbitrary code when an administrator opens Active Directory Users and Computers. Known advanced persistent threat backdoor technique.' `
            -Remediation 'Remove unauthorized entries immediately. Compare against known-good baseline. Investigate Event ID 5136 to determine who modified the entries and when.' `
            -Data $suspects
    } else {
        Write-OK "Display Specifiers: no suspicious entries"
    }
}

#endregion

#region ── CHECK: Fine-Grained Password Policy Weaknesses ─────────────────────

function Invoke-CheckFineGrainedPolicies {
    Write-Status "Checking Fine-Grained Password Policies (PSOs)..."

    $psoRes = Invoke-Searcher -Filter "(objectClass=msDS-PasswordSettings)" `
              -Props @('name','msDS-MinimumPasswordLength','msDS-PasswordComplexityEnabled',
                       'msDS-LockoutThreshold','msDS-PasswordReversibleEncryptionEnabled',
                       'msDS-PasswordHistoryLength','msDS-PSOAppliesTo') `
              -SearchBase "CN=Password Settings Container,CN=System,$Script:NC"

    if ($psoRes.Count -eq 0) { Write-OK "No PSOs configured"; return }

    $weakPSOs = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($r in $psoRes) {
        $name    = Get-Prop $r 'name'
        $minLen  = [int](Get-Prop $r 'msds-minimumpasswordlength')
        $complex = (Get-Prop $r 'msds-passwordcomplexityenabled') -ne $false
        $lockout = [int](Get-Prop $r 'msds-lockoutthreshold')
        $revEnc  = (Get-Prop $r 'msds-passwordreversibleencryptionrequired') -eq $true
        $history = [int](Get-Prop $r 'msds-passwordhistorylength')

        $issues = @()
        if ($minLen  -lt 12)  { $issues += "MinLen=$minLen (should be 12+)" }
        if (-not $complex)    { $issues += "Complexity=disabled" }
        if ($lockout -eq 0)   { $issues += "NoLockout" }
        if ($revEnc)          { $issues += "ReversibleEncryption=enabled" }
        if ($history -lt 10)  { $issues += "HistoryCount=$history (should be 10+)" }

        if ($issues.Count -gt 0) {
            $weakPSOs.Add(@{ PSO=$name; Issues=($issues -join '; '); Applies=@($r[0].Properties['msds-psoappliesTo']).Count }) | Out-Null
        }
    }

    if ($weakPSOs.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'P-WeakPSO' `
            -Title "$($weakPSOs.Count) Fine-Grained Password Policy/PSO with insufficient settings" `
            -Risk 'Medium' `
            -Detail 'PSOs with short minimum length, no complexity, no lockout, or reversible encryption weaken security for their target accounts.' `
            -Remediation 'Review and update each PSO: MinLength >= 14, Complexity = TRUE, Lockout <= 10, History >= 10, ReversibleEncryption = FALSE.' `
            -Data $weakPSOs
    } else {
        Write-OK "PSOs: all have acceptable settings"
    }
}

#endregion



#region ── CHECK: Broad ACL Sweep ─────────────────────────────────────────────

function Invoke-CheckBroadACL {
    Write-Status "Scanning dangerous ACEs on critical AD objects..."

    # Rights bitmasks that constitute dangerous permissions
    $dangerous = @{
        0x000F01FF = 'GenericAll'
        0x00040000 = 'WriteDACL'
        0x00080000 = 'WriteOwner'
        0x00020000 = 'WriteProperty(all)'
        0x00000100 = 'DS-Replication-Get-Changes-All'
    }

    # Well-known SID prefixes to SKIP (legitimate)
    $skip = @(
        'S-1-5-18'   # SYSTEM
        'S-1-5-32-544' # Builtin\Administrators
        'S-1-5-9'    # Enterprise Domain Controllers
    )

    # Pull DomainSID for skip-list expansion
    $domSID = ''
    try { $domSID = $Script:DomainInfo['SID'].ToString() } catch {}
    if ($domSID) {
        $skip += "$domSID-512"  # Domain Admins
        $skip += "$domSID-519"  # Enterprise Admins
        $skip += "$domSID-518"  # Schema Admins
        $skip += "$domSID-516"  # Domain Controllers
        $skip += 'S-1-3-0'     # Creator Owner
    }

    # Targets: domain root + all OUs
    $targets = @()
    $targets += @{ DN = $Script:NC; Label = 'Domain Root' }

    $ous = Invoke-Searcher -Filter '(objectClass=organizationalUnit)' -Props @('distinguishedName','name')
    foreach ($ou in $ous) {
        $targets += @{
            DN    = Get-Prop $ou 'distinguishedname'
            Label = "OU: $(Get-Prop $ou 'name')"
        }
    }

    # Also check all GPO objects
    $gpos = Invoke-Searcher -Filter '(objectClass=groupPolicyContainer)' `
            -Props @('distinguishedName','displayName') `
            -SearchBase "CN=Policies,CN=System,$Script:NC"
    foreach ($gpo in $gpos) {
        $targets += @{
            DN    = Get-Prop $gpo 'distinguishedname'
            Label = "GPO: $(Get-Prop $gpo 'displayname')"
        }
    }

    $dangerousACEs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($target in $targets) {
        try {
            $path = "LDAP://$Script:BindServer/$($target.DN)"
            $de = if ($Script:Cred) {
                New-Object System.DirectoryServices.DirectoryEntry($path,
                    $Script:Cred.UserName, $Script:Cred.GetNetworkCredential().Password)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry($path)
            }
            $acl = $de.ObjectSecurity
            if (-not $acl) { continue }

            foreach ($ace in $acl.Access) {
                $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                if ($skip -contains $sid) { continue }
                $rights = [int]$ace.ActiveDirectoryRights

                # Check if any dangerous bit is set
                $matched = $null
                if (($rights -band 0x000F01FF) -eq 0x000F01FF) { $matched = 'GenericAll' }
                elseif ($rights -band 0x00040000) { $matched = 'WriteDACL' }
                elseif ($rights -band 0x00080000) { $matched = 'WriteOwner' }

                if ($matched) {
                    # Resolve SID to name
                    $name = try { $ace.IdentityReference.ToString() } catch { $sid }
                    $dangerousACEs.Add(@{
                        Object    = $target.Label
                        Principal = $name
                        Right     = $matched
                        Inherited = $ace.IsInherited
                    }) | Out-Null
                }
            }
        } catch { }
    }

    if ($dangerousACEs.Count -gt 0) {
        $nonInherited = @($dangerousACEs | Where-Object { -not $_.Inherited })
        $risk = if ($nonInherited.Count -gt 0) { 'High' } else { 'Medium' }
        Add-Finding -Category 'Security' -RuleId 'S-DangerousACE' `
            -Title "Dangerous ACEs on AD objects ($($dangerousACEs.Count) total, $($nonInherited.Count) non-inherited)" `
            -Risk $risk `
            -Detail "Principals with GenericAll/WriteDACL/WriteOwner on domain root, OUs, or GPOs can modify AD structure, redirect GPOs, or take full control of managed accounts. Non-inherited ACEs are most suspicious." `
            -Remediation 'Review each ACE. Remove GenericAll/WriteDACL/WriteOwner from non-admin principals. Run: (Get-Acl "AD:\<OU DN>").Access | Where ActiveDirectoryRights -match "GenericAll|WriteDACL"' `
            -Data ($nonInherited | Select-Object -First 20)
    } else {
        Write-OK "Broad ACL sweep: no unexpected dangerous ACEs found"
    }
}

#endregion

#region ── CHECK: Sites and Subnets ───────────────────────────────────────────

function Invoke-CheckSitesSubnets {
    Write-Status "Enumerating AD sites and subnets..."

    # Sites
    $sites = Invoke-Searcher -Filter '(objectClass=site)' `
             -Props @('name','whenCreated','description') `
             -SearchBase "CN=Sites,$Script:Config"
    $Script:DomainInfo['SiteCount'] = $sites.Count

    # Subnets
    $subnets = Invoke-Searcher -Filter '(objectClass=subnet)' `
               -Props @('name','siteObject','description') `
               -SearchBase "CN=Subnets,CN=Sites,$Script:Config"

    Write-OK "Sites: $($sites.Count)   Subnets: $($subnets.Count)"

    # Detect orphan subnets (no site association)
    $orphans = @($subnets | Where-Object { -not (Get-Prop $_ 'siteobject') })
    if ($orphans.Count -gt 0) {
        Add-Finding -Category 'Anomalies' -RuleId 'A-OrphanSubnet' `
            -Title "Orphaned subnets — not associated with any AD site ($($orphans.Count))" `
            -Risk 'Low' `
            -Detail "Subnets with no site assignment cause clients to authenticate to DCs in the Default-First-Site, increasing latency and potentially routing auth traffic across WAN links." `
            -Remediation 'Open AD Sites and Services, expand Subnets, right-click each orphan and assign to the correct site.' `
            -Data ($orphans | ForEach-Object { @{ Subnet = Get-Prop $_ 'name'; Description = Get-Prop $_ 'description' } })
    }

    # Very few subnets but many sites = missing mappings
    if ($sites.Count -gt 2 -and $subnets.Count -lt $sites.Count) {
        Add-Finding -Category 'Anomalies' -RuleId 'A-MissingSubnets' `
            -Title "Fewer subnets ($($subnets.Count)) than sites ($($sites.Count)) — potential missing subnet mappings" `
            -Risk 'Low' `
            -Detail "When clients connect from a subnet not defined in AD Sites and Services, the DC locator falls back to the Default-First-Site which may be geographically distant. This can also mask which office/network a device is on." `
            -Remediation 'Run nltest /dsgetdc: from each site to verify correct DC selection. Add missing subnet objects in Active Directory Sites and Services.'
    }
}

#endregion

#region ── CHECK: BitLocker Keys in AD ────────────────────────────────────────

function Invoke-CheckBitLocker {
    Write-Status "Checking BitLocker key (msFVE-RecoveryInformation) exposure..."

    $fveObjects = Invoke-Searcher `
        -Filter '(objectClass=msFVE-RecoveryInformation)' `
        -Props @('distinguishedName','msFVE-RecoveryPassword','msFVE-VolumeGuid','whenCreated','ntsecuritydescriptor')

    if ($fveObjects.Count -eq 0) {
        Write-OK "BitLocker: no msFVE-RecoveryInformation objects found (BitLocker AD backup not configured)"
        return
    }

    Write-OK "BitLocker: $($fveObjects.Count) recovery key(s) stored in AD"

    # Check ACLs on FVE objects — who can read the recovery password?
    $exposedKeys = [System.Collections.Generic.List[hashtable]]::new()
    $skip = @('S-1-5-18','S-1-5-32-544','S-1-5-9')
    $domSID = try { $Script:DomainInfo['SID'].ToString() } catch { '' }
    if ($domSID) { $skip += "$domSID-512"; $skip += "$domSID-519" }

    foreach ($fve in ($fveObjects | Select-Object -First 30)) {
        $dn = Get-Prop $fve 'distinguishedname'
        try {
            $path = "LDAP://$Script:BindServer/$dn"
            $de = if ($Script:Cred) {
                New-Object System.DirectoryServices.DirectoryEntry($path,
                    $Script:Cred.UserName, $Script:Cred.GetNetworkCredential().Password)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry($path)
            }
            $acl = $de.ObjectSecurity
            foreach ($ace in ($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' })) {
                $sid = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
                if ($skip -contains $sid) { continue }
                $rights = [int]$ace.ActiveDirectoryRights
                if ($rights -band 0x10) {  # ReadProperty
                    $exposedKeys.Add(@{
                        KeyDN     = ($dn -replace 'CN=.*?,','')
                        Principal = $ace.IdentityReference.ToString()
                    }) | Out-Null
                    break
                }
            }
        } catch {}
    }

    if ($exposedKeys.Count -gt 0) {
        Add-Finding -Category 'Security' -RuleId 'S-BitLockerACL' `
            -Title "BitLocker recovery keys readable by non-admin principals ($($exposedKeys.Count) key(s))" `
            -Risk 'High' `
            -Detail "msFVE-RecoveryInformation objects contain the BitLocker recovery password for each encrypted drive. A principal with ReadProperty access can retrieve the recovery key and decrypt any drive they physically possess." `
            -Remediation 'Restrict read access on msFVE-RecoveryInformation objects to Helpdesk / Domain Admins only. Use BitLocker Management (MBAM or Microsoft Endpoint Manager) to enforce ACL-protected key escrow.' `
            -Data $exposedKeys
    } else {
        Write-OK "BitLocker keys: access restricted appropriately"
    }
}

#endregion

#region ── CHECK: DNS Zone Security ───────────────────────────────────────────

function Invoke-CheckDNSZones {
    Write-Status "Auditing DNS zones in Active Directory..."

    $zones = Invoke-Searcher `
        -Filter '(objectClass=dnsZone)' `
        -Props @('name','dNSProperty','whenCreated','objectGUID') `
        -SearchBase "DC=DomainDnsZones,$Script:NC"

    if ($zones.Count -eq 0) {
        # Try legacy path
        $zones = Invoke-Searcher `
            -Filter '(objectClass=dnsZone)' `
            -Props @('name','dNSProperty','whenCreated') `
            -SearchBase "CN=MicrosoftDNS,CN=System,$Script:NC"
    }

    $findings = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($zone in $zones) {
        $zname = Get-Prop $zone 'name'
        if ($zname -match '^_msdcs\.|^\.|\.\.$') { continue }  # skip internal zones

        # Check for unsigned zones (no DNSSEC)
        $props = $zone.Properties['dnsproperty']
        $signed = $false
        if ($props) {
            foreach ($p in $props) {
                try {
                    # Property ID 0x12 = ZONE_PROPERTY_NO_REFRESH_INTERVAL, 0x51 = ZONE_PROPERTY_DNSSEC
                    # A signed zone has DNSSEC records; simplistic check on raw bytes
                    if ($p.Length -ge 8 -and $p[4] -eq 0x51) { $signed = $true; break }
                } catch {}
            }
        }

        $findings.Add(@{ Zone = $zname; DNSSECSigned = $signed }) | Out-Null
    }

    if ($findings.Count -gt 0) {
        $unsigned = @($findings | Where-Object { -not $_.DNSSECSigned })
        if ($unsigned.Count -gt 0) {
            Add-Finding -Category 'Security' -RuleId 'S-DNSZoneUnsigned' `
                -Title "AD-integrated DNS zones without DNSSEC ($($unsigned.Count) zone(s))" `
                -Risk 'Low' `
                -Detail "Zones not protected by DNSSEC are vulnerable to DNS spoofing and cache poisoning attacks. Attackers who compromise a DNS server or perform AiTM can redirect internal name resolution." `
                -Remediation 'Enable DNSSEC on critical zones. In DNS Manager: right-click zone > DNSSEC > Sign the Zone. Alternatively use PowerShell: Invoke-DnsServerZoneSign.' `
                -Data ($unsigned | Select-Object -First 15)
        }

        Write-OK "DNS zones found: $($findings.Count) ($($unsigned.Count) unsigned)"
    } else {
        Write-OK "DNS zones: no AD-integrated zones found or accessible"
    }

    # Also check for zone-level insecure dynamic update (supplement to existing DNS check)
    $unsafeDynamic = Invoke-Searcher `
        -Filter '(objectClass=dnsZone)' `
        -Props @('name','dNSProperty') `
        -SearchBase "DC=DomainDnsZones,$Script:NC"

    # Count zones (info only, full insecure-update detection needs DNS WMI which requires remote admin)
    if ($zones.Count -gt 0) {
        Add-Finding -Category 'Anomalies' -RuleId 'A-DNSZoneInventory' `
            -Title "DNS zone inventory: $($zones.Count) AD-integrated zone(s) found" `
            -Risk 'Info' `
            -Detail "AD-integrated DNS zones: $(($findings | ForEach-Object { $_.Zone }) -join ', '). Review each zone for insecure dynamic updates and verify DNSSEC signing status." `
            -Remediation 'Review DNS zone properties in DNS Manager. Disable non-secure dynamic updates on all zones. Enable DNSSEC on public-facing zones.'
    }
}

#endregion


#region ── CHECK: Orphaned adminCount ─────────────────────────────────────────

function Invoke-CheckOrphanedAdminCount {
    Write-Status "Checking for accounts with orphaned adminCount=1..."

    $adminCountAccts = Invoke-Searcher `
        -Filter "(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(samAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        -Props @('sAMAccountName','distinguishedName')

    if (-not $adminCountAccts -or @($adminCountAccts).Count -eq 0) {
        Write-OK "Orphaned adminCount: none found"; return
    }

    $protectedGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
                         'Account Operators','Backup Operators','Print Operators','Server Operators',
                         'Group Policy Creator Owners','Replicator','Cert Publishers',
                         'Read-only Domain Controllers','Denied RODC Password Replication Group')
    $protectedDNs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($grpName in $protectedGroups) {
        $grp = Invoke-Searcher -Filter "(&(objectClass=group)(sAMAccountName=$grpName))" -Props @('member')
        if ($grp) {
            foreach ($g in $grp) {
                if ($g.Properties['member']) { foreach ($m in $g.Properties['member']) { [void]$protectedDNs.Add("$m") } }
            }
        }
    }

    $orphaned = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($u in $adminCountAccts) {
        $dn = "$($u.Properties['distinguishedname'][0])"
        if (-not $protectedDNs.Contains($dn)) {
            $orphaned.Add(@{ Account="$($u.Properties['samaccountname'][0])"; DN=$dn }) | Out-Null
        }
    }

    if ($orphaned.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'S-OrphanAdminCount' `
            -Title "$($orphaned.Count) account(s) carry adminCount=1 but are not in any protected group (ghost privilege)" `
            -Risk 'Medium' `
            -Detail "These accounts previously held privileged group membership. SDProp stamped adminCount=1 and applied a hardened ACL. After removal from the privileged group, adminCount was never cleared. The accounts retain hardened ACLs that block inheritance and appear privileged to auditing tools. A common persistence artefact — attackers add a backdoor account to DA, SDProp fires, they remove it but adminCount persists." `
            -Remediation "For each account: verify it should not be privileged. Then: (1) Set-ADUser -Identity <sam> -Clear adminCount  (2) In ADUC > Account Properties > Security > Advanced, re-enable ACL inheritance." `
            -Data $orphaned
    } else {
        Write-OK "adminCount: no orphaned accounts found"
    }
}

#endregion

#region ── CHECK: Print Spooler on Domain Controllers ─────────────────────────

function Invoke-CheckPrintSpoolerDC {
    Write-Status "Probing Print Spooler service on Domain Controllers..."

    $dcObjects = Invoke-Searcher `
        -Filter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" `
        -Props @('dNSHostName','name')

    $spoolerRunning = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($dc in $dcObjects) {
        $hostname = if ($dc.Properties['dnshostname'].Count -gt 0) { "$($dc.Properties['dnshostname'][0])" } `
                    else { "$($dc.Properties['name'][0])" }
        try {
            $fs = [System.IO.File]::Open("\\$hostname\pipe\spoolss",
                  [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $fs.Close()
            $spoolerRunning.Add(@{ DC=$hostname; Status='Running (pipe open)' }) | Out-Null
        } catch [System.UnauthorizedAccessException] {
            $spoolerRunning.Add(@{ DC=$hostname; Status='Running (pipe exists, access denied)' }) | Out-Null
        } catch { }
    }

    if ($spoolerRunning.Count -gt 0) {
        Add-Finding -Category 'DomainControllers' -RuleId 'S-PrintSpoolerDC' `
            -Title "$($spoolerRunning.Count) DC(s) have Print Spooler running — PrintNightmare / coerce attack surface" `
            -Risk 'High' `
            -Detail "The Print Spooler on DCs enables forced authentication coercion: any domain user can trigger a DC to authenticate outbound to an attacker machine via MS-RPRN or MS-EFSRPC. Combined with unconstrained delegation capture or NTLM relay to LDAP, this achieves full domain compromise without any credentials. Also exposes CVE-2021-34527 (PrintNightmare) for local privilege escalation to SYSTEM." `
            -Remediation "Disable on all DCs: Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled. Enforce via GPO: Computer Config > Windows Settings > System Services > Print Spooler = Disabled. Confirm no print jobs originate from DCs before disabling." `
            -Data $spoolerRunning
    } else {
        Write-OK "Print Spooler: not running on any DC"
    }
}

#endregion

#region ── CHECK: Inactive / Unlinked GPOs ────────────────────────────────────

function Invoke-CheckInactiveGPOs {
    Write-Status "Identifying unlinked Group Policy Objects..."

    $gpoContainer = "CN=Policies,CN=System,$Script:NC"
    $allGPOs = Invoke-Searcher `
        -Filter "(objectClass=groupPolicyContainer)" `
        -Props @('cn','displayName') `
        -SearchBase $gpoContainer

    if (-not $allGPOs -or @($allGPOs).Count -eq 0) { return }

    $allGPOGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $gpoCNtoName = @{}
    foreach ($g in $allGPOs) {
        $guid = "$($g.Properties['cn'][0])".Trim('{}').ToLower()
        [void]$allGPOGuids.Add($guid)
        $name = if ($g.Properties['displayname'].Count -gt 0) { "$($g.Properties['displayname'][0])" } else { $guid }
        $gpoCNtoName[$guid] = $name
    }

    $linkedGuids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Domain root
    $domainObjs = Invoke-Searcher -Filter "(objectClass=domain)" -Props @('gPLink') -SearchBase $Script:NC -Scope 'Base'
    # All OUs
    $ouObjs = Invoke-Searcher -Filter "(objectClass=organizationalUnit)" -Props @('gPLink')
    # Sites (in Configuration NC)
    $siteObjs = Invoke-Searcher -Filter "(objectClass=site)" -Props @('gPLink') -SearchBase $Script:Config

    foreach ($collection in @($domainObjs, $ouObjs, $siteObjs)) {
        if (-not $collection) { continue }
        foreach ($obj in $collection) {
            $gpl = "$($obj.Properties['gplink'][0])"
            if (-not $gpl) { continue }
            $ms = [regex]::Matches($gpl, '\{([0-9a-fA-F\-]{36})\}')
            foreach ($m in $ms) { [void]$linkedGuids.Add($m.Groups[1].Value.ToLower()) }
        }
    }

    $builtIn = @('31b2f340-016d-11d2-945f-00c04fb984f9','6ac1786c-016f-11d2-945f-00c04fb984f9')
    $unlinked = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($guid in $allGPOGuids) {
        if (-not $linkedGuids.Contains($guid) -and $builtIn -notcontains $guid) {
            $unlinked.Add(@{ GPO=$gpoCNtoName[$guid]; GUID=$guid }) | Out-Null
        }
    }

    if ($unlinked.Count -gt 0) {
        Add-Finding -Category 'GPO' -RuleId 'S-InactiveGPO' `
            -Title "$($unlinked.Count) GPO(s) exist but are not linked to any OU, site, or domain" `
            -Risk 'Low' `
            -Detail "Unlinked GPOs are not enforced but remain editable objects in the domain. An attacker or insider with GPO edit rights (e.g. Authenticated Users, delegation leftovers) can modify an unlinked GPO and then link it to a sensitive OU — without creating a detectable new policy. Also indicates GPO sprawl and poor hygiene that complicates incident response." `
            -Remediation "Open GPMC > Group Policy Objects. For each unlinked GPO: (1) Determine if needed — delete if not. (2) If kept, restrict edit delegation to Domain Admins only. (3) Monitor GPO link events (Event ID 5136) via Advanced Audit on DCs." `
            -Data $unlinked
    } else {
        Write-OK "GPOs: all GPOs are linked"
    }
}

#endregion

#region ── CHECK: Foreign Security Principals ──────────────────────────────────

function Invoke-CheckForeignSecurityPrincipals {
    Write-Status "Checking for orphaned Foreign Security Principal objects..."

    $fspBase = "CN=ForeignSecurityPrincipals,$Script:NC"
    $fsps = Invoke-Searcher `
        -Filter "(objectClass=foreignSecurityPrincipal)" `
        -Props @('name','distinguishedName','memberOf') `
        -SearchBase $fspBase

    if (-not $fsps -or @($fsps).Count -eq 0) {
        Write-OK "Foreign Security Principals: none"; return
    }

    # Collect SID prefixes of currently trusted domains
    $trustedSIDPrefixes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $trusts = Invoke-Searcher -Filter "(objectClass=trustedDomain)" -Props @('securityIdentifier') `
              -SearchBase "CN=System,$Script:NC"
    foreach ($td in $trusts) {
        $sidBytes = $td.Properties['securityidentifier'][0]
        if ($sidBytes) {
            try {
                $sid    = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                $prefix = ($sid.ToString() -replace '-\d+$','')
                [void]$trustedSIDPrefixes.Add($prefix)
            } catch {}
        }
    }

    $wellKnown = @('S-1-5-11','S-1-1-0','S-1-5-7','S-1-5-4','S-1-5-2','S-1-5-1','S-1-5-32')
    $orphaned  = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($fsp in $fsps) {
        $sidStr = "$($fsp.Properties['name'][0])"
        $isWK   = $wellKnown | Where-Object { $sidStr.StartsWith($_) }
        if ($isWK) { continue }
        $prefix   = ($sidStr -replace '-\d+$','')
        $isTrusted= $trustedSIDPrefixes.Contains($prefix)
        if (-not $isTrusted) {
            $groups = @($fsp.Properties['memberof'])
            $orphaned.Add(@{
                SID      = $sidStr
                Groups   = if ($groups.Count -gt 0) { ($groups | Select-Object -First 2) -join ' | ' } else { 'None' }
            }) | Out-Null
        }
    }

    if ($orphaned.Count -gt 0) {
        Add-Finding -Category 'Accounts' -RuleId 'S-OrphanFSP' `
            -Title "$($orphaned.Count) Foreign Security Principal(s) reference SIDs from non-trusted domains (orphaned)" `
            -Risk 'Low' `
            -Detail "Orphaned FSPs reference accounts from domains that no longer have an active trust relationship. These objects linger after trust removal and may hold group memberships that grant access rights. In an extreme scenario, if an attacker creates a domain with a matching SID range and re-establishes the trust, these FSPs would grant those attacker accounts the inherited permissions." `
            -Remediation "List FSPs: Get-ADObject -SearchBase 'CN=ForeignSecurityPrincipals,DC=...' -Filter {objectClass -eq 'foreignSecurityPrincipal'} -Properties memberOf. Remove any without a corresponding active trust. Verify no ACLs reference these SIDs before deletion." `
            -Data $orphaned
    } else {
        Write-OK "Foreign Security Principals: no orphaned FSPs found"
    }
}

#endregion

#region ── HTML Report ─────────────────────────────────────────────────────────

function Get-RiskColor {
    param([string]$risk)
    switch ($risk) {
        'Critical' { return '#dc3545' }
        'High'     { return '#fd7e14' }
        'Medium'   { return '#e6a817' }
        'Low'      { return '#20c997' }
        default    { return '#6c757d' }
    }
}

function Get-RiskOrder {
    param([string]$risk)
    switch ($risk) { 'Critical'{0} 'High'{1} 'Medium'{2} 'Low'{3} default{4} }
}

function Get-RiskScore {
    $score = 100
    foreach ($f in $Script:Findings) {
        switch ($f.Risk) {
            'Critical' { $score -= 25 }
            'High'     { $score -= 10 }
            'Medium'   { $score -= 5  }
            'Low'      { $score -= 2  }
        }
    }
    return [Math]::Max(0, $score)
}

function Get-ScoreColor { param([int]$s)
    if ($s -ge 80) { '#28a745' } elseif ($s -ge 60) { '#ffc107' } elseif ($s -ge 40) { '#fd7e14' } else { '#dc3545' }
}

# Build a proper HTML table from an array of hashtables or strings
function Build-DataTable {
    param([object[]]$Items, [int]$Max = 50)
    if (-not $Items -or $Items.Count -eq 0) { return '' }
    $sample = $Items[0]
    $limited = $Items | Select-Object -First $Max
    $total   = $Items.Count

    if ($sample -is [hashtable]) {
        $cols = @($sample.Keys) | Select-Object -First 6
        $hdr  = ($cols | ForEach-Object { "<th>$(HE $_)</th>" }) -join ''
        $rows = ($limited | ForEach-Object {
            $row = $_
            $cells = ($cols | ForEach-Object {
                $v = if ($row.ContainsKey($_)) { "$($row[$_])" } else { '' }
                "<td>$(HE $v)</td>"
            }) -join ''
            "<tr>$cells</tr>"
        }) -join ''
        $more = if ($total -gt $Max) { "<tr class='more-row'><td colspan='$($cols.Count)'>... and $($total - $Max) more</td></tr>" } else { '' }
        return "<div class='data-tbl-wrap'><table class='data-tbl'><thead><tr>$hdr</tr></thead><tbody>$rows$more</tbody></table></div>"
    } else {
        $rows = ($limited | ForEach-Object { "<tr><td>$(HE "$_")</td></tr>" }) -join ''
        $more = if ($total -gt $Max) { "<tr class='more-row'><td>... and $($total - $Max) more</td></tr>" } else { '' }
        return "<div class='data-tbl-wrap'><table class='data-tbl'><tbody>$rows$more</tbody></table></div>"
    }
}

function Build-FindingRows {
    $sb   = [System.Text.StringBuilder]::new()
    $idx  = 0
    $all  = $Script:Findings | Sort-Object { Get-RiskOrder $_.Risk }, Category

    foreach ($f in $all) {
        $idx++
        $color   = Get-RiskColor $f.Risk
        $ttp     = if ($Script:MitreTTPMap.ContainsKey($f.RuleId)) { $Script:MitreTTPMap[$f.RuleId] } else { '' }
        $ttpLink = if ($ttp) {
            $tid = $ttp.Replace('.','/')
            "<a class='ttp-link' href='https://attack.mitre.org/techniques/$tid/' target='_blank'>$ttp</a>"
        } else { '<span class="ttp-none">—</span>' }

        $dataItems = if ($f.Data) { @($f.Data) } else { @() }
        $hasData   = $dataItems.Count -gt 0
        $dataHtml  = if ($hasData) { Build-DataTable -Items $dataItems } else { '' }
        $dataBadge = if ($hasData) { "<span class='data-count'>$($dataItems.Count) affected</span>" } else { '' }

        # Remediation as numbered steps
        $remedHtml = '<ol class="remed-list">'
        $f.Remediation -split '(?<=[.;])\s+(?=[0-9]\)|[A-Z])' | ForEach-Object {
            if ($_.Trim()) { $remedHtml += "<li>$(HE $_.Trim())</li>" }
        }
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
    $(if ($hasData) { "<div class='affected-wrap'><div class='affected-lbl'>Affected Objects ($($dataItems.Count))</div>$dataHtml</div>" })
    <div class="remed-wrap">
      <div class="remed-lbl">Remediation Steps</div>
      $remedHtml
    </div>
  </div>
</div>
"@)
    }
    return $sb.ToString()
}

function Build-OsTable {
    if (-not $Script:OsCounts -or $Script:OsCounts.Count -eq 0) { return '<p class="no-data">No OS data collected</p>' }
    $rows = $Script:OsCounts.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        $pct = [Math]::Round($_.Value / [Math]::Max(1,$Script:ComputerStats.Total) * 100)
        "<tr><td>$(HE $_.Key)</td><td>$($_.Value)</td><td><div class='bar-wrap'><div class='bar' style='width:$pct%'></div></div></td></tr>"
    }
    return "<table class='info-tbl'><thead><tr><th>Operating System</th><th>Count</th><th style='width:40%'>Distribution</th></tr></thead><tbody>$($rows -join '')</tbody></table>"
}

function Build-TrustTable {
    if (-not $Script:Trusts -or $Script:Trusts.Count -eq 0) { return '<p class="no-data">No domain trusts found</p>' }
    $rows = $Script:Trusts | ForEach-Object {
        $sfBadge = if ($_.SIDFilter) { '<span class="pill ok">Enabled</span>' } else { '<span class="pill bad">Disabled</span>' }
        "<tr><td><strong>$(HE $_.Partner)</strong></td><td>$($_.Type)</td><td>$($_.Direction)</td><td>$sfBadge</td></tr>"
    }
    return "<table class='info-tbl'><thead><tr><th>Partner Domain</th><th>Type</th><th>Direction</th><th>SID Filtering</th></tr></thead><tbody>$($rows -join '')</tbody></table>"
}

function Build-DCTable {
    if (-not $Script:DCList -or $Script:DCList.Count -eq 0) { return '<p class="no-data">No DCs collected</p>' }
    $rows = $Script:DCList | ForEach-Object {
        $rodc = if ($_.IsRODC) { '<span class="pill warn">RODC</span>' } else { '' }
        $ll   = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') } else { 'N/A' }
        "<tr><td><strong>$(HE $_.Name)</strong> $rodc</td><td>$(HE $_.OS)</td><td>$ll</td><td>$(HE $_.DN)</td></tr>"
    }
    return "<table class='info-tbl'><thead><tr><th>Name</th><th>OS</th><th>Last Logon</th><th>Distinguished Name</th></tr></thead><tbody>$($rows -join '')</tbody></table>"
}

function New-HTMLReport {
    param([string]$OutputFile)

    $score      = Get-RiskScore
    $scoreColor = Get-ScoreColor $score
    $critical   = ($Script:Findings | Where-Object Risk -eq 'Critical').Count
    $high       = ($Script:Findings | Where-Object Risk -eq 'High').Count
    $medium     = ($Script:Findings | Where-Object Risk -eq 'Medium').Count
    $low        = ($Script:Findings | Where-Object Risk -eq 'Low').Count
    $info       = ($Script:Findings | Where-Object Risk -eq 'Info').Count
    $elapsed    = [Math]::Round((New-TimeSpan -Start $StartTime -End (Get-Date)).TotalSeconds)

    $fl = switch ([int]$Script:DomainInfo['FunctionalLevel']) {
        0 {'Windows 2000'} 1 {'Windows 2003 Mixed'} 2 {'Windows 2003'}
        3 {'Windows 2008'} 4 {'Windows 2008 R2'}    5 {'Windows 2012'}
        6 {'Windows 2012 R2'} 7 {'Windows 2016'}   10 {'Windows 2025'}
        default { "Level $([int]$Script:DomainInfo['FunctionalLevel'])" }
    }

    # SVG score ring  (r=54, circumference=339.3)
    $circ   = 339.3
    $filled = [Math]::Round($circ * $score / 100, 1)
    $gap    = $circ - $filled

    $findingRowsHtml  = Build-FindingRows
    $dcTableHtml      = Build-DCTable
    $trustTableHtml   = Build-TrustTable
    $osTableHtml      = Build-OsTable
    $failedModuleHtml = ''
    if ($Script:FailedModules.Count -gt 0) {
        $frows = ($Script:FailedModules | ForEach-Object {
            "<tr><td><code>$($_.Name)</code></td><td style='color:#dc3545'>$(HE $_.Error)</td><td>$($_.Line)</td></tr>"
        }) -join ''
        $failedModuleHtml = "<section class='section'><h2 class='section-h warn-h'>&#9888; Modules With Errors ($($Script:FailedModules.Count))</h2><p class='note'>These modules errored during execution. Findings may be incomplete for these areas.</p><table class='info-tbl'><thead><tr><th>Module</th><th>Error</th><th>Line</th></tr></thead><tbody>$frows</tbody></table></section>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD-Recon — $Domain</title>
<style>
:root{
  --c:#dc3545;--h:#fd7e14;--m:#e6a817;--l:#20c997;--i:#6c757d;
  --bg:#f4f6fb;--card:#fff;--border:#e0e4ed;--text:#1a1d23;--sub:#5a6375;
  --hdr1:#0f2444;--hdr2:#1a3a6b;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,Arial,sans-serif;background:var(--bg);color:var(--text);font-size:14px}
a{color:#1a6bbf;text-decoration:none}a:hover{text-decoration:underline}

/* ── Header ── */
.hdr{background:linear-gradient(135deg,var(--hdr1),var(--hdr2));color:#fff;padding:28px 40px 24px;display:flex;align-items:center;gap:36px;flex-wrap:wrap}
.hdr-text h1{font-size:1.7rem;font-weight:800;letter-spacing:-.3px}
.hdr-text p{opacity:.75;margin-top:6px;font-size:.88rem}
.hdr-meta{display:flex;gap:20px;margin-top:10px;flex-wrap:wrap}
.hdr-meta span{font-size:.8rem;opacity:.8}
.hdr-meta b{opacity:1}
.score-ring{flex-shrink:0;text-align:center}
.score-ring svg{display:block}
.score-num{font-size:1.6rem;font-weight:900;fill:$scoreColor}
.score-lbl{font-size:.6rem;fill:rgba(255,255,255,.6);text-transform:uppercase;letter-spacing:.5px}

/* ── Stats bar ── */
.stats-bar{background:#fff;border-bottom:1px solid var(--border);padding:0 40px;display:flex;flex-wrap:wrap}
.stat-item{padding:16px 24px;display:flex;flex-direction:column;align-items:center;border-right:1px solid var(--border);cursor:pointer;transition:background .15s;min-width:100px}
.stat-item:hover{background:#f8f9fc}
.stat-item.active{border-bottom:3px solid #1a6bbf;padding-bottom:13px}
.stat-num{font-size:1.6rem;font-weight:800;line-height:1}
.stat-lbl{font-size:.72rem;color:var(--sub);margin-top:3px;text-transform:uppercase;letter-spacing:.4px}
.sc{color:var(--c)} .sh{color:var(--h)} .sm{color:var(--m)} .sl{color:var(--l)} .si{color:var(--i)}

/* ── Toolbar ── */
.toolbar{background:#fff;border-bottom:1px solid var(--border);padding:10px 40px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;position:sticky;top:0;z-index:50;box-shadow:0 2px 8px rgba(0,0,0,.06)}
.search-box{flex:1;min-width:200px;max-width:380px;position:relative}
.search-box input{width:100%;padding:7px 12px 7px 34px;border:1px solid var(--border);border-radius:6px;font-size:.87rem;outline:none}
.search-box input:focus{border-color:#1a6bbf;box-shadow:0 0 0 3px rgba(26,107,191,.1)}
.search-icon{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--sub);font-size:.9rem}
.filter-btns{display:flex;gap:6px;flex-wrap:wrap}
.fbtn{padding:5px 14px;border-radius:20px;border:1.5px solid var(--border);background:#fff;font-size:.78rem;font-weight:600;cursor:pointer;transition:all .15s}
.fbtn:hover{border-color:#1a6bbf;color:#1a6bbf}
.fbtn.active{border-color:currentColor;color:#fff}
.fbtn-all.active{background:#1a6bbf;border-color:#1a6bbf}
.fbtn-critical.active{background:var(--c);border-color:var(--c)}
.fbtn-high.active{background:var(--h);border-color:var(--h)}
.fbtn-medium.active{background:var(--m);border-color:var(--m)}
.fbtn-low.active{background:var(--l);border-color:var(--l)}
.fbtn-info.active{background:var(--i);border-color:var(--i)}
.toolbar-right{margin-left:auto;display:flex;gap:8px}
.btn{padding:6px 14px;border-radius:6px;border:1.5px solid var(--border);background:#fff;font-size:.8rem;cursor:pointer;font-weight:600;transition:all .15s;display:flex;align-items:center;gap:5px}
.btn:hover{border-color:#1a6bbf;color:#1a6bbf}
.btn-primary{background:#1a6bbf;border-color:#1a6bbf;color:#fff}
.btn-primary:hover{background:#155ba0}

/* ── Layout ── */
.container{max-width:1400px;margin:0 auto;padding:24px 40px}
.section{background:var(--card);border:1px solid var(--border);border-radius:10px;margin-bottom:20px;overflow:hidden}
.section-h{font-size:1rem;font-weight:700;padding:14px 20px;border-bottom:1px solid var(--border);background:#f8f9fc;display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none}
.section-h .toggle-icon{margin-left:auto;color:var(--sub);font-size:.8rem;transition:transform .2s}
.warn-h{background:#fff8f0;color:#b35c00;border-bottom-color:#fde5c8}

/* ── Info grid ── */
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:0;padding:0}
.info-col{padding:16px 20px}
.info-col:first-child{border-right:1px solid var(--border)}
.info-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px dashed var(--border);font-size:.87rem}
.info-row:last-child{border-bottom:none}
.info-key{color:var(--sub)}
.info-val{font-weight:600;text-align:right}
.info-val.bad{color:var(--c)}
.info-val.warn{color:var(--h)}
.info-val.ok{color:#28a745}

/* ── Info table ── */
.info-tbl{width:100%;border-collapse:collapse;font-size:.87rem}
.info-tbl th{background:#f8f9fc;padding:9px 14px;text-align:left;font-weight:600;border-bottom:2px solid var(--border);font-size:.8rem;text-transform:uppercase;letter-spacing:.3px;color:var(--sub)}
.info-tbl td{padding:9px 14px;border-bottom:1px solid #f0f2f8}
.info-tbl tr:last-child td{border-bottom:none}
.info-tbl tr:hover td{background:#f8f9fc}
.note{padding:10px 20px;font-size:.85rem;color:var(--sub)}
.no-data{padding:20px;color:var(--sub);font-style:italic;text-align:center}

/* ── Pill / badge ── */
.pill{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.72rem;font-weight:700;letter-spacing:.2px}
.pill.ok{background:#d4edda;color:#155724}
.pill.bad{background:#f8d7da;color:#721c24}
.pill.warn{background:#fff3cd;color:#856404}
.bar-wrap{background:#e9ecef;border-radius:4px;height:8px;overflow:hidden}
.bar{background:#1a6bbf;height:100%;border-radius:4px}

/* ── Finding cards ── */
.findings-toolbar{padding:12px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#f8f9fc}
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
.finding-hdr:hover{background:#f4f6fb}
.chevron{color:var(--sub);font-size:.75rem;transition:transform .18s;flex-shrink:0}
.chevron.open{transform:rotate(90deg)}
.risk-pill{display:inline-block;padding:3px 11px;border-radius:20px;font-size:.72rem;font-weight:700;color:#fff;white-space:nowrap;flex-shrink:0}
.rule-id{font-family:'Cascadia Code','Consolas',monospace;font-size:.78rem;color:var(--sub);background:#f0f2f8;padding:2px 8px;border-radius:4px;white-space:nowrap;flex-shrink:0}
.finding-title{font-weight:600;font-size:.92rem;flex:1;min-width:200px}
.finding-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-left:auto;flex-shrink:0}
.cat-tag{padding:2px 9px;border-radius:10px;background:#eef1fb;color:#3a4a7a;font-size:.72rem;font-weight:600}
.data-count{padding:2px 9px;border-radius:10px;background:#fff3cd;color:#856404;font-size:.72rem;font-weight:700;white-space:nowrap}
.ttp-link{padding:2px 8px;border-radius:4px;background:#e8f0fe;color:#1a6bbf;font-size:.72rem;font-weight:700;border:1px solid #c5d8f7;white-space:nowrap}
.ttp-none{color:#bbb;font-size:.8rem}

/* ── Finding body ── */
.finding-body{padding:0 20px 18px 52px;background:#fafbfd}
.finding-desc{color:#3a4050;font-size:.87rem;line-height:1.65;margin-bottom:14px;padding-top:12px;border-top:1px dashed var(--border)}
.affected-wrap{margin-bottom:14px}
.affected-lbl{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--sub);margin-bottom:6px}
.data-tbl-wrap{overflow-x:auto;border-radius:6px;border:1px solid var(--border)}
.data-tbl{width:100%;border-collapse:collapse;font-size:.82rem}
.data-tbl th{background:#f0f2f8;padding:7px 12px;text-align:left;font-weight:600;color:var(--sub);border-bottom:1px solid var(--border);font-size:.75rem;text-transform:uppercase;letter-spacing:.3px}
.data-tbl td{padding:7px 12px;border-bottom:1px solid #f0f2f8;color:var(--text);font-family:'Cascadia Code','Consolas',monospace;font-size:.8rem}
.data-tbl tr:last-child td{border-bottom:none}
.data-tbl tr:hover td{background:#f4f6fb}
.more-row td{color:var(--sub);font-style:italic;text-align:center;padding:6px;font-family:inherit}
.remed-wrap{background:#f0fff4;border:1px solid #c3e6cb;border-radius:6px;padding:12px 16px}
.remed-lbl{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#155724;margin-bottom:8px}
.remed-list{padding-left:18px;color:#1e5631;font-size:.85rem;line-height:1.7}
.remed-list li{margin-bottom:4px}

/* ── No results ── */
.no-results{padding:40px;text-align:center;color:var(--sub);display:none}

/* ── Footer ── */
.footer{text-align:center;padding:24px;font-size:.8rem;color:var(--sub);border-top:1px solid var(--border);background:#fff;margin-top:8px}
.footer strong{color:var(--text)}

@media(max-width:768px){
  .hdr,.toolbar,.container{padding-left:16px;padding-right:16px}
  .stats-bar{padding:0 16px}
  .info-grid{grid-template-columns:1fr}
  .info-col:first-child{border-right:none;border-bottom:1px solid var(--border)}
  .finding-body{padding-left:16px}
}
@media print{
  .toolbar,.btn{display:none}
  .finding-body{display:block !important}
}
</style>
</head>
<body>

<!-- ── Header ── -->
<div class="hdr">
  <div class="score-ring">
    <svg width="100" height="100" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,.15)" stroke-width="10"/>
      <circle cx="60" cy="60" r="54" fill="none" stroke="$scoreColor" stroke-width="10"
              stroke-dasharray="$filled $gap" stroke-linecap="round"
              transform="rotate(-90 60 60)"/>
      <text x="60" y="56" text-anchor="middle" dominant-baseline="middle" class="score-num">$score</text>
      <text x="60" y="74" text-anchor="middle" class="score-lbl">/ 100</text>
    </svg>
  </div>
  <div class="hdr-text">
    <h1>AD Security Audit — $Domain</h1>
    <p>Active Directory security assessment report</p>
    <div class="hdr-meta">
      <span><b>DC:</b> $Script:BindServer</span>
      <span><b>Generated:</b> $(Get-Date -Format 'yyyy-MM-dd HH:mm')</span>
      <span><b>Duration:</b> ${elapsed}s</span>
      <span><b>Functional Level:</b> $fl</span>
    </div>
  </div>
</div>

<!-- ── Stats bar ── -->
<div class="stats-bar">
  <div class="stat-item" onclick="setFilter('critical')" title="Filter Critical findings">
    <span class="stat-num sc">$critical</span><span class="stat-lbl">Critical</span></div>
  <div class="stat-item" onclick="setFilter('high')" title="Filter High findings">
    <span class="stat-num sh">$high</span><span class="stat-lbl">High</span></div>
  <div class="stat-item" onclick="setFilter('medium')" title="Filter Medium findings">
    <span class="stat-num sm">$medium</span><span class="stat-lbl">Medium</span></div>
  <div class="stat-item" onclick="setFilter('low')" title="Filter Low findings">
    <span class="stat-num sl">$low</span><span class="stat-lbl">Low</span></div>
  <div class="stat-item" onclick="setFilter('info')" title="Filter Info findings">
    <span class="stat-num si">$info</span><span class="stat-lbl">Info</span></div>
  <div class="stat-item"><span class="stat-num">$($Script:UserStats.Total)</span><span class="stat-lbl">Users</span></div>
  <div class="stat-item"><span class="stat-num">$($Script:ComputerStats.Total)</span><span class="stat-lbl">Computers</span></div>
  <div class="stat-item"><span class="stat-num">$($Script:DCList.Count)</span><span class="stat-lbl">DCs</span></div>
  <div class="stat-item"><span class="stat-num">$($Script:Trusts.Count)</span><span class="stat-lbl">Trusts</span></div>
</div>

<!-- ── Toolbar ── -->
<div class="toolbar" id="main-toolbar">
  <div class="search-box">
    <span class="search-icon">&#128269;</span>
    <input type="text" id="searchInput" placeholder="Search findings..." oninput="applyFilters()">
  </div>
  <div class="filter-btns">
    <button class="fbtn fbtn-all active" onclick="setFilter('all')">All ($($Script:Findings.Count))</button>
    <button class="fbtn fbtn-critical" onclick="setFilter('critical')">Critical ($critical)</button>
    <button class="fbtn fbtn-high" onclick="setFilter('high')">High ($high)</button>
    <button class="fbtn fbtn-medium" onclick="setFilter('medium')">Medium ($medium)</button>
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

<!-- ── Domain Info ── -->
<div class="section">
  <h2 class="section-h" onclick="toggleSection(this)">Domain Information <span class="toggle-icon">&#9660;</span></h2>
  <div class="section-body">
    <div class="info-grid">
      <div class="info-col">
        <div class="info-row"><span class="info-key">Domain FQDN</span><span class="info-val">$Domain</span></div>
        <div class="info-row"><span class="info-key">Functional Level</span><span class="info-val $(if([int]$Script:DomainInfo['FunctionalLevel'] -lt 7){'warn'}else{'ok'})">$fl</span></div>
        <div class="info-row"><span class="info-key">Schema Version</span><span class="info-val">$($Script:DomainInfo['SchemaVersion'])</span></div>
        <div class="info-row"><span class="info-key">Recycle Bin</span><span class="info-val $(if($Script:DomainInfo['RecycleBin']){'ok'}else{'bad'})">$(if($Script:DomainInfo['RecycleBin']){'Enabled'}else{'Disabled'})</span></div>
        <div class="info-row"><span class="info-key">krbtgt Password Age</span><span class="info-val $(if([int]$Script:DomainInfo['KrbtgtPwdAge'] -gt 180){'bad'}elseif([int]$Script:DomainInfo['KrbtgtPwdAge'] -gt 90){'warn'}else{'ok'})">$($Script:DomainInfo['KrbtgtPwdAge']) days</span></div>
        <div class="info-row"><span class="info-key">Machine Account Quota</span><span class="info-val $(if([int]$Script:DomainInfo['MAQ'] -ne 0){'warn'}else{'ok'})">$($Script:DomainInfo['MAQ'])</span></div>
      </div>
      <div class="info-col">
        <div class="info-row"><span class="info-key">Min Password Length</span><span class="info-val $(if([int]$Script:DomainInfo['MinPwdLength'] -lt 12){'bad'}else{'ok'})">$($Script:DomainInfo['MinPwdLength']) chars</span></div>
        <div class="info-row"><span class="info-key">Password Complexity</span><span class="info-val $(if($Script:DomainInfo['PwdComplexity']){'ok'}else{'bad'})">$($Script:DomainInfo['PwdComplexity'])</span></div>
        <div class="info-row"><span class="info-key">Password History</span><span class="info-val">$($Script:DomainInfo['PwdHistory']) remembered</span></div>
        <div class="info-row"><span class="info-key">Lockout Threshold</span><span class="info-val $(if([int]$Script:DomainInfo['LockoutThreshold'] -eq 0){'bad'}else{'ok'})">$(if([int]$Script:DomainInfo['LockoutThreshold'] -eq 0){'None (unlimited)'}else{"$($Script:DomainInfo['LockoutThreshold']) attempts"})</span></div>
        <div class="info-row"><span class="info-key">Protected Users Group</span><span class="info-val">$($Script:DomainInfo['ProtectedUserCount'])</span></div>
        <div class="info-row"><span class="info-key">Users with SID History</span><span class="info-val $(if([int]$Script:DomainInfo['SIDHistoryCount'] -gt 0){'warn'}else{'ok'})">$($Script:DomainInfo['SIDHistoryCount'])</span></div>
      </div>
    </div>
  </div>
</div>

<!-- ── Domain Controllers ── -->
<div class="section">
  <h2 class="section-h" onclick="toggleSection(this)">Domain Controllers ($($Script:DCList.Count)) <span class="toggle-icon">&#9660;</span></h2>
  <div class="section-body">$dcTableHtml</div>
</div>

<!-- ── Trusts ── -->
<div class="section">
  <h2 class="section-h" onclick="toggleSection(this)">Domain Trusts ($($Script:Trusts.Count)) <span class="toggle-icon">&#9660;</span></h2>
  <div class="section-body">$trustTableHtml</div>
</div>

<!-- ── OS Inventory ── -->
<div class="section">
  <h2 class="section-h" onclick="toggleSection(this)">Computer OS Inventory ($($Script:ComputerStats.Total) total) <span class="toggle-icon">&#9660;</span></h2>
  <div class="section-body">$osTableHtml</div>
</div>

<!-- ── Security Findings ── -->
<div class="section" id="findings-section">
  <h2 class="section-h" style="cursor:default">
    Security Findings
    <span id="findings-visible-count" style="font-weight:400;color:var(--sub);font-size:.85rem;margin-left:6px"></span>
  </h2>
  <div class="findings-toolbar">
    <span class="findings-count" id="results-label">Showing $($Script:Findings.Count) findings</span>
  </div>
  <div class="findings-list" id="findings-list">
$findingRowsHtml
    <div class="no-results" id="no-results">No findings match the current filter.</div>
  </div>
</div>

$failedModuleHtml

</div><!-- /container -->

<div class="footer">
  <strong>AD-Recon by Harsh P</strong> &nbsp;|&nbsp; <a href="https://github.com/MrHarshvardhan" target="_blank">github.com/MrHarshvardhan</a> &nbsp;|&nbsp;
  Score: $score/100 &nbsp;|&nbsp;
  $($Script:Findings.Count) findings ($critical Critical, $high High, $medium Medium, $low Low) &nbsp;|&nbsp;
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
</div>

<script>
// ── State ──────────────────────────────────────────────────────────
var currentFilter = 'all';
var searchTerm    = '';

// ── Toggle single finding ──────────────────────────────────────────
function toggleFinding(hdr) {
  var body    = hdr.nextElementSibling;
  var chevron = hdr.querySelector('.chevron');
  var open    = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  chevron.classList.toggle('open', !open);
}

// ── Expand / Collapse all visible ─────────────────────────────────
function expandAll() {
  document.querySelectorAll('.finding-card:not([style*="display:none"]) .finding-hdr').forEach(function(h){
    h.nextElementSibling.style.display = 'block';
    h.querySelector('.chevron').classList.add('open');
  });
}
function collapseAll() {
  document.querySelectorAll('.finding-body').forEach(function(b){ b.style.display = 'none'; });
  document.querySelectorAll('.chevron').forEach(function(c){ c.classList.remove('open'); });
}

// ── Section collapse ──────────────────────────────────────────────
function toggleSection(hdr) {
  var body = hdr.nextElementSibling;
  var icon = hdr.querySelector('.toggle-icon');
  var open = body.style.display !== 'none';
  body.style.display = open ? 'none' : '';
  icon.innerHTML     = open ? '&#9650;' : '&#9660;';
}

// ── Filter ────────────────────────────────────────────────────────
function setFilter(risk) {
  currentFilter = risk;
  document.querySelectorAll('.fbtn').forEach(function(b){ b.classList.remove('active'); });
  var active = document.querySelector('.fbtn-'+risk);
  if (active) active.classList.add('active');
  applyFilters();
}

function applyFilters() {
  searchTerm = document.getElementById('searchInput').value.toLowerCase();
  var cards   = document.querySelectorAll('.finding-card');
  var visible = 0;
  cards.forEach(function(card) {
    var riskMatch = (currentFilter === 'all' || card.dataset.risk === currentFilter);
    var text      = card.querySelector('.finding-hdr').textContent.toLowerCase() +
                    card.querySelector('.finding-body').textContent.toLowerCase();
    var textMatch = !searchTerm || text.indexOf(searchTerm) !== -1;
    var show = riskMatch && textMatch;
    card.style.display = show ? '' : 'none';
    if (show) visible++;
  });
  document.getElementById('results-label').textContent =
    'Showing ' + visible + ' of ' + cards.length + ' findings';
  document.getElementById('no-results').style.display = visible === 0 ? 'block' : 'none';
}

// ── Export CSV ────────────────────────────────────────────────────
function exportCSV() {
  var rows = [['Risk','Rule ID','Title','Category','MITRE ATT&CK','Affected Count','Detail']];
  document.querySelectorAll('.finding-card').forEach(function(card) {
    var hdr     = card.querySelector('.finding-hdr');
    var risk    = (card.querySelector('.risk-pill') || {}).textContent || '';
    var ruleId  = (card.querySelector('.rule-id') || {}).textContent || '';
    var title   = (card.querySelector('.finding-title') || {}).textContent || '';
    var cat     = (card.querySelector('.cat-tag') || {}).textContent || '';
    var ttp     = (card.querySelector('.ttp-link') || {}).textContent || '';
    var cnt     = (card.querySelector('.data-count') || {}).textContent || '';
    var desc    = (card.querySelector('.finding-desc') || {}).textContent.trim() || '';
    rows.push([risk, ruleId, title, cat, ttp, cnt, desc]);
  });
  var csv = rows.map(function(r){
    return r.map(function(c){ return '"'+String(c).replace(/"/g,'""')+'"'; }).join(',');
  }).join('\r\n');
  var blob = new Blob([csv], {type:'text/csv'});
  var a    = document.createElement('a');
  a.href   = URL.createObjectURL(blob);
  a.download = 'ADRecon-Findings.csv';
  a.click();
}

// ── Init ─────────────────────────────────────────────────────────
applyFilters();
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding UTF8
}

#endregion

#region ── Main Execution ──────────────────────────────────────────────────────

$Script:Trusts         = @()
$Script:PSOs           = @()
$Script:AdminUsers     = @()
$Script:OsCounts       = @{}
$Script:FailedModules  = [System.Collections.Generic.List[hashtable]]::new()

# Run checks (skip if requested)
$checks = @(
    @{ Name='DomainInfo';         Fn={ Invoke-CheckDomainInfo } }
    @{ Name='DomainControllers';  Fn={ Invoke-CheckDomainControllers } }
    @{ Name='Krbtgt';             Fn={ Invoke-CheckKrbtgt } }
    @{ Name='Users';              Fn={ Invoke-CheckUsers } }
    @{ Name='Computers';          Fn={ Invoke-CheckComputers } }
    @{ Name='Groups';             Fn={ Invoke-CheckGroups; Invoke-CheckSensitiveGroups } }
    @{ Name='BuiltinAccounts';    Fn={ Invoke-CheckBuiltinAccounts } }
    @{ Name='Delegation';         Fn={ Invoke-CheckDelegation } }
    @{ Name='Kerberos';           Fn={ Invoke-CheckKerberosEncryption } }
    @{ Name='Security';           Fn={ Invoke-CheckDCSync; Invoke-CheckAdminSDHolder; Invoke-CheckSecuritySettings } }
    @{ Name='GPOSecurity';        Fn={ Invoke-CheckGPOSecurity } }
    @{ Name='GPPPasswords';       Fn={ Invoke-CheckGPPPasswords } }
    @{ Name='ShadowCredentials';  Fn={ Invoke-CheckShadowCredentials } }
    @{ Name='Trusts';             Fn={ Invoke-CheckTrusts } }
    @{ Name='PKI';                Fn={ Invoke-CheckPKI; Invoke-CheckADCSExtended } }
    @{ Name='Exchange';           Fn={ Invoke-CheckExchangePermissions } }
    @{ Name='RODC';               Fn={ Invoke-CheckRODC } }
    @{ Name='AzureAD';            Fn={ Invoke-CheckAzureADConnect } }
    @{ Name='DNS';                Fn={ Invoke-CheckDNSSecurity } }
    @{ Name='LAPS';               Fn={ Invoke-CheckLAPSACL } }
    @{ Name='DisplaySpecifiers';  Fn={ Invoke-CheckDisplaySpecifiers } }
    @{ Name='FinePwdPolicy';      Fn={ Invoke-CheckFineGrainedPolicies } }
    @{ Name='FSMO';               Fn={ Invoke-CheckFSMO } }
    @{ Name='BroadACL';          Fn={ Invoke-CheckBroadACL } }
    @{ Name='SitesSubnets';      Fn={ Invoke-CheckSitesSubnets } }
    @{ Name='BitLocker';         Fn={ Invoke-CheckBitLocker } }
    @{ Name='DNSZones';          Fn={ Invoke-CheckDNSZones } }
    @{ Name='OrphanAdminCount';  Fn={ Invoke-CheckOrphanedAdminCount } }
    @{ Name='PrintSpoolerDC';    Fn={ Invoke-CheckPrintSpoolerDC } }
    @{ Name='InactiveGPOs';      Fn={ Invoke-CheckInactiveGPOs } }
    @{ Name='ForeignSPs';        Fn={ Invoke-CheckForeignSecurityPrincipals } }
)

foreach ($check in $checks) {
    if ($SkipChecks -contains $check.Name) {
        Write-Host "  [--] Skipping: $($check.Name)" -ForegroundColor DarkGray
        continue
    }
    try {
        & $check.Fn
    } catch {
        $errMsg = $_.Exception.Message
        $errLine = $_.InvocationInfo.ScriptLineNumber
        Write-Host "  [!] Module '$($check.Name)' failed (line $errLine): $errMsg" -ForegroundColor Red
        $Script:FailedModules.Add(@{
            Name  = $check.Name
            Error = $errMsg
            Line  = $errLine
        }) | Out-Null
    }
}

# Generate report
$timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportFile = Join-Path $OutputPath "ADRecon_${Domain}_${timestamp}.html"

Write-Status "Generating HTML report..."
New-HTMLReport -OutputFile $reportFile

$score = Get-RiskScore
$crit  = ($Script:Findings | Where-Object Risk -eq 'Critical').Count
$hi    = ($Script:Findings | Where-Object Risk -eq 'High').Count

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║              AD-Recon Results  —  by Harsh P            ║" -ForegroundColor Cyan
Write-Host "  ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host ("  ║  Security Score  : " + "$score / 100".PadRight(36) + "║") -ForegroundColor (if($score -ge 70){'Green'}elseif($score -ge 40){'Yellow'}else{'Red'})
Write-Host ("  ║  Total Findings  : " + "$($Script:Findings.Count)  ($crit Critical, $hi High)".PadRight(36) + "║") -ForegroundColor Cyan
Write-Host ("  ║  Failed Modules  : " + "$($Script:FailedModules.Count)".PadRight(36) + "║") -ForegroundColor (if($Script:FailedModules.Count -gt 0){'Yellow'}else{'Green'})
Write-Host ("  ║  Report Saved    : ").PadRight(58) -ForegroundColor Cyan -NoNewline; Write-Host "║" -ForegroundColor Cyan
Write-Host "  ╟──────────────────────────────────────────────────────────╢" -ForegroundColor Cyan
Write-Host "  ║  $($reportFile.Substring([Math]::Max(0,$reportFile.Length-52)).PadRight(54))  ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if ($Script:FailedModules.Count -gt 0) {
    Write-Host "  Failed modules (check errors above for details):" -ForegroundColor Yellow
    $Script:FailedModules | ForEach-Object {
        Write-Host "    - $($_.Name): $($_.Error)" -ForegroundColor DarkYellow
    }
    Write-Host ""
}

#endregion
