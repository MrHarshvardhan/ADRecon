# AD-Recon

> Community-built Active Directory & Azure AD security audit toolkit — no third-party tools, no RSAT required.

---

## What is AD-Recon?

**AD-Recon** is a PowerShell script that scans your Active Directory (or Azure AD) environment for security misconfigurations and generates a single self-contained HTML report — like a health check for your domain.

- No installation, no extra tools, no admin rights required
- Works with just a standard domain user account
- Report opens in any browser, works fully offline

| Script | What it audits | How it connects |
|--------|---------------|-----------------|
| `Invoke-ADRecon.ps1` | On-premises Active Directory | LDAP (built-in .NET, no RSAT) |
| `Invoke-AzureADRecon.ps1` | Entra ID / Azure AD | Microsoft Graph API |

---

## Quick Start — Run Directly from GitHub

No need to clone the repo. Run directly in PowerShell:

### On-premises Active Directory

```powershell
# One-liner: download and run immediately
irm https://raw.githubusercontent.com/MrHarshvardhan/ADRecon/master/Invoke-ADRecon.ps1 | iex
```

```powershell
# Or: download the file first, then run
Invoke-WebRequest -Uri https://raw.githubusercontent.com/MrHarshvardhan/ADRecon/master/Invoke-ADRecon.ps1 `
                  -OutFile Invoke-ADRecon.ps1
.\Invoke-ADRecon.ps1
```

### Azure AD / Entra ID

```powershell
# One-liner: download and run with browser login popup
irm https://raw.githubusercontent.com/MrHarshvardhan/ADRecon/master/Invoke-AzureADRecon.ps1 | iex
```

```powershell
# Or: download first, then run interactively
Invoke-WebRequest -Uri https://raw.githubusercontent.com/MrHarshvardhan/ADRecon/master/Invoke-AzureADRecon.ps1 `
                  -OutFile Invoke-AzureADRecon.ps1
.\Invoke-AzureADRecon.ps1 -UseDeviceCode -OpenBrowser
```

> **Execution policy note:** If PowerShell blocks the script, run this first:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
> ```

---

## Step-by-Step Guide — Active Directory Audit

### Step 1 — Open PowerShell

Open **PowerShell** (not CMD). You do not need to run as Administrator.

### Step 2 — Download the script

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/MrHarshvardhan/ADRecon/master/Invoke-ADRecon.ps1 `
                  -OutFile Invoke-ADRecon.ps1
```

### Step 3 — Run it

**Option A — Audit your current domain (simplest, no extra parameters)**
```powershell
.\Invoke-ADRecon.ps1
```
Runs as your currently logged-in user against the domain your machine is joined to.

**Option B — Audit with a specific user account**
```powershell
.\Invoke-ADRecon.ps1 -Username "CORP\auditor" -Password "P@ssw0rd!"
```

**Option C — Audit a remote domain or specific domain controller**
```powershell
.\Invoke-ADRecon.ps1 -Server "dc01.corp.local" -Username "CORP\auditor" -Password "P@ssw0rd!"
```

### Step 4 — Open the report

The script generates an HTML file in the same folder:
```
ADRecon_corp.local_20240115_143022.html
```
Open it in any browser. No internet connection needed.

---

## Step-by-Step Guide — Azure AD / Entra ID Audit

### Step 1 — Download the script

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/MrHarshvardhan/ADRecon/master/Invoke-AzureADRecon.ps1 `
                  -OutFile Invoke-AzureADRecon.ps1
```

### Step 2 — Choose your login method

#### Method 1 — Interactive login with browser popup (recommended for desktops)

```powershell
.\Invoke-AzureADRecon.ps1 -UseDeviceCode -OpenBrowser
```

**What happens:**
1. Script prints a one-time code in the terminal
2. Your default browser opens automatically to `https://microsoft.com/devicelogin`
3. Enter the code and sign in with your Azure AD account
4. Come back to the terminal — the audit starts automatically

#### Method 2 — Interactive login without popup (for servers / SSH sessions)

```powershell
.\Invoke-AzureADRecon.ps1 -UseDeviceCode
```

**What happens:**
1. Script prints a URL and a one-time code:
   ```
   To sign in, open https://microsoft.com/devicelogin
   and enter the code: ABCD1234XY
   ```
2. Open the URL in any browser on any device
3. Enter the code and sign in
4. Audit starts automatically once login is complete

#### Method 3 — App registration (automated / scheduled audits)

Create an App Registration in Azure Portal with read-only permissions, then:

```powershell
.\Invoke-AzureADRecon.ps1 -TenantId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
                           -ClientId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
                           -ClientSecret "your-client-secret-here"
```

Required Graph API permissions for the app (all read-only):

| Permission | Used for |
|------------|---------|
| `Directory.Read.All` | Users, groups, roles, devices |
| `Policy.Read.All` | Conditional Access policies |
| `AuditLog.Read.All` | Sign-in risk, audit logs |
| `RoleManagement.Read.All` | PIM role assignments |
| `Application.Read.All` | App secrets and permissions |
| `UserAuthenticationMethod.Read.All` | Per-user MFA status |

#### Method 4 — Reuse an existing Microsoft Graph session

```powershell
# If you already ran Connect-MgGraph earlier in the same session:
Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","AuditLog.Read.All","RoleManagement.Read.All","Application.Read.All","UserAuthenticationMethod.Read.All"
.\Invoke-AzureADRecon.ps1
```

#### Which method should I use?

| Your situation | Use this |
|---------------|---------|
| Running on your own Windows/Mac laptop | `-UseDeviceCode -OpenBrowser` |
| Running on a server or over SSH | `-UseDeviceCode` |
| Scheduling an automated scan | `-TenantId` + `-ClientId` + `-ClientSecret` |
| Already signed in via Connect-MgGraph | No parameters needed |

### Step 3 — Open the report

```
AzureADRecon_<TenantId>_20240115_143022.html
```
Open in any browser — no internet needed.

---

## More Examples

### Save the report to a specific folder

```powershell
.\Invoke-ADRecon.ps1 -OutputPath "C:\Audits\2024"
.\Invoke-AzureADRecon.ps1 -UseDeviceCode -OutputPath "C:\Audits\2024"
```

### Skip specific checks

```powershell
# Skip GPP password and PKI checks (e.g., if SYSVOL access is restricted)
.\Invoke-ADRecon.ps1 -SkipChecks "Invoke-CheckGPPPasswords","Invoke-CheckPKI"
```

### Audit a specific domain by FQDN

```powershell
.\Invoke-ADRecon.ps1 -Domain "subsidiary.corp.local"
```

### Audit with a pre-built credential object (no plaintext password in command)

```powershell
$cred = Get-Credential
.\Invoke-ADRecon.ps1 -Credential $cred
```

### Disable colored output (for logging / CI pipelines)

```powershell
.\Invoke-ADRecon.ps1 -NoColor
```

---

## What the Report Shows

Both scripts generate a **self-contained HTML report**:

- **Risk score** (0–100) shown as a ring gauge — higher is better
- **Stats bar** — total users, computers, groups, DCs at a glance
- **Findings** — each issue shown as a collapsible card with:
  - Risk level (Critical / High / Medium / Low / Info)
  - MITRE ATT&CK technique ID (linked to attack.mitre.org)
  - Affected objects listed in a table (usernames, computer names, file paths, etc.)
  - Step-by-step remediation guide
- **Filter bar** — filter by risk level or search by keyword
- **Export CSV** — download all findings as a spreadsheet

---

## What It Checks

### Active Directory — 31 Security Modules

| # | Module | What It Detects |
|---|--------|-----------------|
| 1 | Domain Info | Domain functional level, tombstone lifetime, recycle bin |
| 2 | Domain Controllers | Missing patches, SMB signing, LDAP signing, outdated OS |
| 3 | Krbtgt | Password age > 180 days, never-changed krbtgt |
| 4 | Users | No pre-auth (AS-REP), reversible encryption, DES-only, password never expires, stale accounts |
| 5 | Computers | Outdated OS (XP/2003/Vista/2008), old password, unconstrained delegation |
| 6 | Groups | Large groups, empty groups, non-admin members of Domain Admins |
| 7 | Delegation | Unconstrained, constrained, resource-based constrained delegation |
| 8 | DCSync | Non-DC accounts with Replicating Directory Changes All |
| 9 | AdminSDHolder | Modified AdminSDHolder ACL (backdoor persistence) |
| 10 | Trusts | External trusts, SID history enabled, SID filtering disabled |
| 11 | PKI / ADCS | ESC1–8 misconfigurations, expired CAs, weak key sizes |
| 12 | Security Settings | WDigest plaintext, NTLMv1, null sessions, WPAD, anonymous enumeration |
| 13 | FSMO | FSMO role holders, time sync, RID pool consumption |
| 14 | Sensitive Groups | Schema Admins, Account Operators, Backup Operators membership |
| 15 | Builtin Accounts | Default Administrator/Guest account status |
| 16 | GPP Passwords | MS14-025: cPassword in SYSVOL (cleartext passwords in Group Policy) |
| 17 | Kerberos Encryption | RC4-only policies, AES not required |
| 18 | GPO Security | Missing LAPS, AppLocker, Credential Guard, no screen lock GPO |
| 19 | Exchange | RBAC WriteDACL/FullControl delegation (PrivExchange) |
| 20 | ADCS Extended | Template anomalies, duplicate OIDs, manager approval bypass |
| 21 | RODC | RODC password replication policy, privileged accounts cached |
| 22 | Shadow Credentials | msDS-KeyCredentialLink on non-DC objects (persistence) |
| 23 | Azure AD Connect | Stale sync, AZUREADSSOACC account (Pass-Through Auth) |
| 24 | DNS Security | Wildcard records (WPAD), insecure dynamic update settings |
| 25 | LAPS ACL | Who can read the LAPS ms-Mcs-AdmPwd attribute |
| 26 | Display Specifiers | Malicious script hooks in display specifiers |
| 27 | Fine-Grained PSOs | Password policies weaker than domain default |
| 28 | Broad ACL | GenericAll / WriteDACL / WriteOwner on OUs and GPOs |
| 29 | Sites & Subnets | AD site topology, orphaned subnets |
| 30 | BitLocker ACL | Who can read BitLocker recovery keys from AD |
| 31 | DNS Zones | DNSSEC status, zone inventory |

### Azure AD / Entra ID — 11 Security Modules

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

### `Invoke-ADRecon.ps1`
- Windows PowerShell 5.1+ or PowerShell 7+
- No RSAT, no AD module, no third-party tools
- Network access to a domain controller on port 389 (LDAP)
- Standard domain user account (read-only access is enough for most checks)

### `Invoke-AzureADRecon.ps1`
- PowerShell 5.1+ or PowerShell 7+
- Internet access to `login.microsoftonline.com` and `graph.microsoft.com`
- An Azure AD account (or app registration) with the read-only permissions listed above

---

## Parameters Reference

### `Invoke-ADRecon.ps1`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Domain` | String | *(current domain)* | Target AD domain FQDN, e.g. `corp.local` |
| `-Server` | String | *(auto-detected)* | DC hostname or IP to connect to |
| `-Username` | String | *(current user)* | Alternate username in `DOMAIN\user` format |
| `-Password` | String | *(none)* | Alternate password |
| `-Credential` | PSCredential | *(none)* | Pre-built credential object from `Get-Credential` |
| `-OutputPath` | String | *(current folder)* | Folder where the HTML report is saved |
| `-SkipChecks` | String[] | *(none)* | List of module names to skip |
| `-NoColor` | Switch | *(false)* | Disable colored console output |

### `Invoke-AzureADRecon.ps1`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-TenantId` | String | *(none)* | Entra ID tenant GUID |
| `-ClientId` | String | *(none)* | App registration client ID |
| `-ClientSecret` | String | *(none)* | App registration secret |
| `-CertificateThumbprint` | String | *(none)* | Certificate-based auth thumbprint |
| `-UseDeviceCode` | Switch | *(false)* | Interactive login — prints URL + code in terminal |
| `-OpenBrowser` | Switch | *(false)* | Auto-open `microsoft.com/devicelogin` in your browser (use with `-UseDeviceCode`) |
| `-OutputPath` | String | *(current folder)* | Folder where the HTML report is saved |
| `-SkipChecks` | String[] | *(none)* | List of module names to skip |

---

## Risk Scoring

Each finding reduces the score from a starting point of 100:

| Level | Score Impact | Examples |
|-------|-------------|---------|
| Critical | −20 | DCSync rights, AS-REP Roasting, ADCS ESC1, null sessions |
| High | −10 | Unconstrained delegation, krbtgt password age > 180 days, WDigest enabled |
| Medium | −5 | Missing LAPS, password never expires, outdated OS |
| Low | −2 | Empty groups, weak PSO |
| Info | 0 | Informational findings only |

A domain with no issues scores **100**. Most real environments score between **40–80**.

---

## Architecture

```
Invoke-ADRecon.ps1
│
├── ADSI / DirectorySearcher  (no RSAT — works with any domain user)
├── 31 isolated check modules (each in try/catch — one failure never stops the rest)
├── Add-Finding collector
└── HTML report generator (fully self-contained, no CDN, works offline)

Invoke-AzureADRecon.ps1
│
├── Microsoft Graph REST API
│   ├── Auth: Device code | Client credentials | MgGraph session
│   └── Auto-pagination (handles tenants with thousands of objects)
├── 11 isolated check modules
├── Add-Finding collector
└── HTML report generator (same design, Azure blue theme)
```

---

## Contributing

Pull requests welcome. When adding a new check module:

1. Name it `Invoke-Check<Topic>` (e.g., `Invoke-CheckKerberoast`)
2. Wrap all logic in `try/catch` — never throw; call `Add-Finding` for each issue found
3. Use `Invoke-Searcher` for LDAP queries (handles credentials and DC binding automatically)
4. Add the module to the `$checks` array in the main execution block
5. Add a MITRE ATT&CK mapping entry to `$Script:MitreTTPMap` if applicable

---

## Legal / Disclaimer

> **For authorized security assessments only.**
>
> Only run this tool against domains and tenants for which you have explicit written authorization. Unauthorized use is illegal in most jurisdictions.

---

## Author

GitHub: [github.com/MrHarshvardhan](https://github.com/MrHarshvardhan)
Built on BloodHound documentation, Microsoft's own security baselines, and AD attack research.

---

*AD-Recon by Harsh P — community AD security audit toolkit*
