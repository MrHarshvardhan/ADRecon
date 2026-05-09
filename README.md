# AD-Recon

> Community-built Active Directory security audit toolkit — no third-party tools, no RSAT required.

---

## Overview

**AD-Recon** is a self-contained PowerShell script that performs a comprehensive security audit of an Active Directory environment and outputs a single self-contained HTML report. It replicates (and extends) the checks performed by enterprise tools like PingCastle, using only built-in .NET ADSI / DirectorySearcher APIs.

A companion script, **AzureAD-Recon**, covers Microsoft Entra ID (Azure AD) via the Microsoft Graph API.

| Script | Target | Auth |
|--------|--------|------|
| `Invoke-ADRecon.ps1` | On-prem Active Directory | Domain credentials / ADSI |
| `Invoke-AzureADRecon.ps1` | Entra ID / Azure AD | Graph API (device code, app secret, or MgGraph) |

---

## Features

### AD Security Checks (27 modules)

| # | Module | What It Detects |
|---|--------|-----------------|
| 1 | Domain Info | Domain functional level, tombstone lifetime, recycle bin |
| 2 | Domain Controllers | Missing patches, SMB signing, LDAP signing, outdated OS |
| 3 | Krbtgt | Password age > 180 days, never-changed krbtgt |
| 4 | Users | Accounts with no pre-auth, reversible encryption, DES-only, password never expires, stale accounts |
| 5 | Computers | Outdated OS (XP/2003/Vista/2008), old password, unconstrained delegation |
| 6 | Groups | Large groups, empty groups, non-admin members of Domain Admins |
| 7 | Delegation | Unconstrained, constrained, resource-based constrained delegation |
| 8 | DCSync | Non-DC accounts with Replicating Directory Changes All |
| 9 | AdminSDHolder | Modified AdminSDHolder ACL (backdoor persistence) |
| 10 | Trusts | External trusts, SID history enabled, SID filtering disabled |
| 11 | PKI / ADCS | ESC1–8 misconfigurations, expired CAs, weak key sizes |
| 12 | Security Settings | WDigest plaintext, NTLMv1 allowed, null sessions, WPAD, anonymous enumeration |
| 13 | FSMO | FSMO role holders, time sync, RID pool consumption |
| 14 | Sensitive Groups | Schema Admins, Account Operators, Backup Operators membership |
| 15 | Builtin Accounts | Default Administrator/Guest account status |
| 16 | GPP Passwords | MS14-025: cPassword in SYSVOL (cleartext passwords) |
| 17 | Kerberos Encryption | RC4-only policies, AES not required |
| 18 | GPO Security | Missing LAPS, AppLocker, Credential Guard, no screen lock |
| 19 | Exchange | RBAC: WriteDACL/FullControl delegation (PrivExchange) |
| 20 | ADCS Extended | Template anomalies, duplicate OIDs, manager approval bypass |
| 21 | RODC | RODC password replication policy, privileged accounts cached |
| 22 | Shadow Credentials | msDS-KeyCredentialLink on non-DC objects (persistence) |
| 23 | Azure AD Connect | Stale sync, AZUREADSSOACC account (Pass-Through Auth) |
| 24 | DNS Security | Wildcard records (WPAD), insecure update settings |
| 25 | LAPS ACL | Who can read the LAPS ms-Mcs-AdmPwd attribute |
| 26 | Display Specifiers | Malicious script hooks in display specifiers |
| 27 | Fine-Grained PSOs | Password policies weaker than domain default |

### Azure AD / Entra ID Checks (11 modules)

| # | Module | What It Detects |
|---|--------|-----------------|
| 1 | Tenant Info | Security defaults enabled/disabled, org settings |
| 2 | Privileged Roles | >5 Global Admins, service principals / guests in privileged roles |
| 3 | MFA | Admins without MFA, tenant-wide MFA registration rate |
| 4 | Conditional Access | Missing MFA policy, legacy auth not blocked, report-only policies |
| 5 | Applications | Expired secrets, 200-year secrets, high-privilege app permissions |
| 6 | Guest Settings | Invite policy, guests as Members, stale guest accounts |
| 7 | Auth Methods | SMS still enabled, no named locations defined |
| 8 | Hybrid Identity | Connect sync staleness, password sync staleness, PTA agent health |
| 9 | PIM | No P2 license, P2 licensed but PIM not activated |
| 10 | Risky Users | Confirmed-compromised accounts, high-risk users (Identity Protection) |
| 11 | Domains | Federated domains, cloud passwords set to never expire |

---

## Requirements

### AD Script (`Invoke-ADRecon.ps1`)
- Windows PowerShell 5.1+ or PowerShell 7+
- **No RSAT, no AD module, no third-party tools required**
- Network access to LDAP (port 389/636) on a domain controller
- Read access to the domain (standard domain user is sufficient for most checks)
- Write/SMB access not required

### Azure AD Script (`Invoke-AzureADRecon.ps1`)
- PowerShell 5.1+ or PowerShell 7+
- One of the following:
  - An active `Connect-MgGraph` session (Microsoft.Graph module)
  - Entra ID App Registration with client credentials (ClientId + ClientSecret or Certificate)
  - Interactive device-code login (prompts in browser)
- Required Graph API permissions (read-only):
  `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `IdentityRiskyUser.Read.All`, `PrivilegedAccess.Read.AzureAD`

---

## Quick Start

### Audit current domain (logged-in user)

```powershell
.\Invoke-ADRecon.ps1
```

### Audit with alternate credentials

```powershell
.\Invoke-ADRecon.ps1 -Username "CORP\auditor" -Password "P@ssw0rd!"
```

### Audit remote domain / specific DC

```powershell
.\Invoke-ADRecon.ps1 -Server "dc01.corp.local" -Username "CORP\auditor" -Password "P@ssw0rd!"
```

### Skip specific checks

```powershell
.\Invoke-ADRecon.ps1 -SkipChecks "Invoke-CheckGPPPasswords","Invoke-CheckPKI"
```

### Save report to specific folder

```powershell
.\Invoke-ADRecon.ps1 -OutputPath "C:\Audits\2024"
```

### Azure AD — device code (interactive, manual browser)

Script prints a URL and a one-time code in the terminal. You open the URL in any browser and type the code.

```powershell
.\Invoke-AzureADRecon.ps1 -UseDeviceCode
```

**Terminal output example:**
```
  [*] Starting device code authentication...

  To sign in, use a web browser to open the page https://microsoft.com/devicelogin
  and enter the code ABCD1234XY to authenticate.
```

### Azure AD — device code with automatic browser popup

Same as above, but the script opens `https://microsoft.com/devicelogin` in your default browser automatically. Works on Windows, macOS, and Linux (requires `xdg-open`).

```powershell
.\Invoke-AzureADRecon.ps1 -UseDeviceCode -OpenBrowser
```

**What happens:**
1. Script requests a device code from Microsoft
2. Prints the one-time code in the terminal
3. Automatically opens `https://microsoft.com/devicelogin` in your default browser
4. You enter the code and sign in with your Azure AD account
5. Script detects the completed login and starts the audit

> **Note**: `-OpenBrowser` is optional. If the browser cannot be opened (e.g., headless server, SSH session), the script falls back gracefully and asks you to open the URL manually. No credentials are stored anywhere.

### Azure AD — app registration (unattended / scheduled)

For automated or scheduled audits — no interactive login required.

```powershell
.\Invoke-AzureADRecon.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
                           -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
                           -ClientSecret "your-secret-here"
```

**Required Graph API permissions (read-only) for the app registration:**

| Permission | Why |
|------------|-----|
| `Directory.Read.All` | Users, groups, roles, devices |
| `Policy.Read.All` | Conditional Access, auth methods |
| `AuditLog.Read.All` | Sign-in risk data |
| `RoleManagement.Read.All` | PIM role assignments |
| `Application.Read.All` | App secrets, high-priv permissions |
| `UserAuthenticationMethod.Read.All` | Per-user MFA status |

### Azure AD — reuse existing MgGraph session

```powershell
Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","AuditLog.Read.All"
.\Invoke-AzureADRecon.ps1
```

### Azure AD — authentication decision guide

| Scenario | Recommended method |
|----------|--------------------|
| Quick one-off audit on your desktop | `-UseDeviceCode -OpenBrowser` |
| Headless server / SSH / no GUI | `-UseDeviceCode` (copy URL+code manually) |
| Scheduled / automated audit | `-ClientId` + `-ClientSecret` (app registration) |
| Already have an MgGraph session open | No parameters needed |

---

## Credential Setup (Editing the Script)

If you prefer to embed credentials directly for lab/testing use, open the script and locate the `param()` block at the top:

```powershell
[string]$Password = '',     # Replace <password> with your password here
```

Change `''` to your password. The script auto-builds a `PSCredential` object from Username + Password when both are provided.

> **Warning**: Never commit credentials to source control. For production use, pass credentials at runtime with `-Username` / `-Password` parameters or use a secrets manager.

---

## Output

Both scripts generate a **self-contained HTML report** in the current directory (or `-OutputPath`):

- `ADRecon_<DomainName>_<Timestamp>.html`
- `AzureADRecon_<TenantId>_<Timestamp>.html`

The report includes:
- **Risk score** (0–100) displayed as a ring gauge
- **Statistics grid** (users, computers, groups, DCs)
- **Findings table** grouped by category with Risk level (Critical / High / Medium / Low / Info)
- **Remediation guidance** for each finding
- **Failed modules** section (checks that errored are listed but don't stop the audit)
- No external CDN / internet dependency — fully offline-safe

---

## Parameters Reference

### `Invoke-ADRecon.ps1`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Domain` | String | *(current)* | Target AD domain FQDN |
| `-Server` | String | *(auto)* | DC hostname or IP |
| `-Username` | String | *(current user)* | Alternate username (DOMAIN\user) |
| `-Password` | String | *(none)* | Alternate password |
| `-Credential` | PSCredential | *(none)* | Pre-built credential object |
| `-OutputPath` | String | *(current dir)* | Folder for HTML report |
| `-SkipChecks` | String[] | *(none)* | Module names to skip |
| `-NoColor` | Switch | *(false)* | Disable console colors |

### `Invoke-AzureADRecon.ps1`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-TenantId` | String | *(none)* | Entra ID tenant GUID |
| `-ClientId` | String | *(none)* | App registration client ID |
| `-ClientSecret` | String | *(none)* | App registration secret |
| `-CertificateThumbprint` | String | *(none)* | Certificate-based auth |
| `-UseDeviceCode` | Switch | *(false)* | Prompt for device-code login (prints URL + code in terminal) |
| `-OpenBrowser` | Switch | *(false)* | Auto-open `microsoft.com/devicelogin` in default browser (use with `-UseDeviceCode`) |
| `-OutputPath` | String | *(current dir)* | Folder for HTML report |
| `-SkipChecks` | String[] | *(none)* | Module names to skip |

---

## Risk Scoring

Each finding is assigned a risk level:

| Level | Score Impact | Typical Examples |
|-------|-------------|-----------------|
| Critical | -20 | DCSync rights, AS-REP Roasting, ESC1, null sessions |
| High | -10 | Unconstrained delegation, krbtgt age > 180d, WDigest |
| Medium | -5 | GPO missing LAPS, password never expires, old OS |
| Low | -2 | Empty groups, info-level config |
| Info | 0 | Informational observations |

A domain with no findings scores 100. Real environments typically score 40–80.

---

## Architecture

```
Invoke-ADRecon.ps1
│
├── ADSI / DirectorySearcher  (no RSAT dependency)
├── 27 isolated check modules (each in try/catch)
├── Central Add-Finding collector
└── HTML report generator (self-contained)

Invoke-AzureADRecon.ps1
│
├── Microsoft Graph REST API
│   ├── Token: MgGraph session | Client credentials | Device code
│   └── Auto-pagination (Get-GraphAll)
├── 11 isolated check modules
├── Central Add-Finding collector
└── HTML report generator (self-contained)
```

---

## Comparison with PingCastle

| Feature | AD-Recon | PingCastle |
|---------|----------|------------|
| License | Open / Community | Source-available (custom license) |
| Language | PowerShell | C# (.NET) |
| RSAT required | No | No |
| External tools | None | None |
| ADCS checks | ESC1–8 | ESC1–8 |
| Azure AD checks | Via separate script | Built-in |
| HTML report | Yes | Yes |
| JSON output | No | Yes |
| SMTP scoring | Custom | Proprietary algorithm |
| Authentication | ADSI + Graph | ADSI + Graph |

---

## Legal / Disclaimer

> **This tool is for authorized security assessments only.**
>
> Only run this script against domains and tenants for which you have explicit written authorization. Unauthorized use against systems you do not own or have permission to audit is illegal in most jurisdictions.

---

## Contributing

Pull requests welcome. When adding a new check module:

1. Follow the naming convention: `Invoke-Check<Topic>`
2. Wrap all logic in `try/catch` — never throw; call `Add-Finding` for findings
3. Use `Invoke-Searcher` for LDAP queries (handles credentials and server binding automatically)
4. Add the function to the `$checks` array in the main execution block
5. Document the LDAP filter and UAC bit used in comments

---

## Author

Tool: AD-Recon / AzureAD-Recon  
Built on techniques from PingCastle, BloodHound documentation, and Microsoft's own security baselines.

---

*AD-Recon by Harsh — community AD security audit toolkit*
