# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

**Need4Admin** is a cross-platform PowerShell security auditing tool for scanning privileged users in Microsoft Entra ID (formerly Azure AD) and Azure subscriptions. This is a fork of the original Windows-only tool by Vlad Johansen, extended with full macOS and Linux support.

**Version:** 1.0-pesip.1
**Original Author:** Vlad Johansen
**Fork Maintainer:** pesip

## Core Functionality

The script audits privileged users and generates comprehensive HTML and CSV reports including:
- Entra ID active and eligible role assignments
- Azure active and eligible role assignments
- MFA status and authentication methods
- Phishing-resistant authentication method detection
- Account status (enabled/disabled, cloud/hybrid)
- Sign-in activity (last interactive/non-interactive)
- PIM group-based role assignments

## Running the Script

### Basic Usage

```bash
# Interactive authentication (both Entra ID and Azure)
pwsh ./Need4Admin_V1.0.ps1

# Entra ID only (skip Azure connection when prompted)
pwsh ./Need4Admin_V1.0.ps1
# Then respond 'N' when asked about Azure scanning

# Service principal authentication with certificate
pwsh ./Need4Admin_V1.0.ps1 -TenantId "tenant-id" -ClientId "app-id" -CertificateThumbprint "thumbprint"
```

### Prerequisites

The script will automatically prompt to install missing modules if needed.

**Required PowerShell Modules:**
- `Az.Accounts` (2.12.0+)
- `Az.Resources` (6.0.0+)
- `Microsoft.Graph.Authentication` (2.15.0+)
- `Microsoft.Graph.Users` (2.15.0+)
- `Microsoft.Graph.Groups` (2.15.0+)
- `Microsoft.Graph.Identity.DirectoryManagement` (2.15.0+)
- `Microsoft.Graph.Identity.SignIns` (2.15.0+)
- `Microsoft.Graph.Reports` (2.15.0+)

**Microsoft Graph Scopes Required:**
- `Directory.Read.All`
- `User.Read.All`
- `UserAuthenticationMethod.Read.All`
- `RoleManagement.Read.Directory`
- `RoleManagement.Read.All`
- `RoleEligibilitySchedule.Read.Directory`
- `RoleAssignmentSchedule.Read.Directory`
- `AuditLog.Read.All`
- `Reports.Read.All`
- `Group.Read.All`

## Cross-Platform Architecture

### Platform Detection

The script automatically detects the operating system using PowerShell's built-in variables:
- `$IsWindows` - Windows platform
- `$IsMacOS` - macOS platform
- `$IsLinux` - Linux platform
- PowerShell version check for backwards compatibility with Windows PowerShell 5.1

### Module Path Configuration

**Windows:** `$env:USERPROFILE\Documents\WindowsPowerShell\Modules`
**macOS/Linux:** `$HOME/.local/share/powershell/Modules`

The script dynamically adjusts `$env:PSModulePath` based on the detected platform.

### HTML Report Opening

The script uses platform-specific commands to open generated HTML reports:
- **Windows:** `Start-Process`
- **macOS:** `open`
- **Linux:** `xdg-open`

### Module Loading Strategy

The script uses a resilient module loading approach:
1. Attempts to load modules with `-MinimumVersion` (not `-RequiredVersion`)
2. Falls back to loading any available version if version requirements fail
3. Suppresses assembly loading warnings for cleaner output
4. Loads Az modules before Microsoft.Graph modules to prevent conflicts

## Script Architecture

### Privileged Roles Monitored

The script tracks 31 privileged Entra ID roles stored in the `$PrivRoles` hashtable (line 61-92), including:
- Global Administrator
- Privileged Role Administrator
- Security Administrator
- Conditional Access Administrator
- And 27 other high-privilege roles

### Key Functions

**`Get-MFAInfo`** (line 290-375)
- Retrieves user authentication methods via Microsoft Graph beta API
- Detects MFA-enabled users (any method beyond password/email)
- Identifies phishing-resistant methods (FIDO2, Windows Hello, Passkeys)
- Returns formatted list of authentication methods

### Report Generation

The script generates two output files with timestamps:
- **HTML Report:** Interactive table with search, sort, column resize capabilities
- **CSV Export:** Raw data export for further analysis

**HTML Features:**
- Color-coded risk indicators (red for no MFA, green for MFA enabled)
- Sortable columns with ascending/descending toggle
- Real-time search/filter functionality
- Resizable columns
- Summary statistics section

### Data Processing Flow

1. **Authentication:** Connect to Microsoft Graph (and optionally Azure)
2. **Role Discovery:** Retrieve all privileged role definitions
3. **Assignment Retrieval:** Get active and eligible role assignments
4. **User Enumeration:** Process each unique user with role assignments
5. **Data Enrichment:** Add MFA status, authentication methods, sign-in data
6. **Azure Scanning:** If connected, retrieve Azure role assignments at subscription level
7. **Report Generation:** Build HTML/CSV reports with collected data
8. **Cleanup:** Disconnect from Graph and Azure

## Testing Approach

This is a standalone script without a formal test suite. When modifying:

1. **Test on multiple platforms:** Verify Windows, macOS, and Linux compatibility
2. **Module loading:** Test with and without pre-installed modules
3. **Authentication paths:** Test both interactive and service principal auth
4. **Azure optional:** Ensure script completes successfully with/without Azure connection
5. **Report generation:** Validate HTML opens correctly on each platform
6. **Error handling:** Test with insufficient permissions to verify graceful failures

## Known Platform-Specific Considerations

### macOS/Linux
- Requires PowerShell Core 7.0+ (not Windows PowerShell 5.1)
- Module installation requires user confirmation on first run
- Linux requires `xdg-utils` package for HTML report opening

### Windows
- Works with both Windows PowerShell 5.1 and PowerShell Core 7+
- May have module version conflicts in `Documents\WindowsPowerShell\Modules` folder
- Script includes fallback logic to handle version conflicts gracefully

## Security Considerations

This is a **defensive security auditing tool** designed to:
- Identify privileged users lacking MFA
- Highlight risky authentication methods
- Detect hybrid identity accounts (potential attack path)
- Provide visibility into role assignments (including PIM-eligible)

The script requires read-only permissions and does not modify any configurations.