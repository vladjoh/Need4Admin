# Need4Admin - Privileged User Scanner (macOS/Linux Fork)

## 🍎 pesip Fork - Cross-Platform Edition

This is a **macOS and Linux compatible fork** of the original [Need4Admin](https://github.com/vladjohansen/Need4Admin) PowerShell script by Vlad Johansen.

**Version:** 1.0-pesip.1
**Original Author:** Vlad Johansen
**Fork Maintainer:** pesip
**Fork Repository:** https://github.com/pesip/Need4Admin

---

## 🎯 What's Different in This Fork?

This fork adds **full cross-platform support** while maintaining 100% compatibility with the original Windows version:

### ✅ New Features in v1.0-pesip.1

| Feature | Windows (Original) | macOS/Linux (Fork) |
|---------|-------------------|-------------------|
| Module Path Detection | `$env:USERPROFILE\Documents\WindowsPowerShell\Modules` | `$HOME/.local/share/powershell/Modules` |
| HTML Report Opening | `Start-Process` | `open` (macOS) / `xdg-open` (Linux) |
| Module Loading | Fixed version requirement | MinimumVersion with fallback for version conflicts |
| Assembly Warnings | Visible | Suppressed for cleaner output |

### 🔧 Technical Changes

1. **Platform Detection**: Automatic detection of Windows/macOS/Linux using `$IsWindows`, `$IsMacOS`, `$IsLinux`
2. **Module Path Handling**: Cross-platform PowerShell module path configuration
3. **Enhanced Module Loading**: Graceful handling of module version conflicts
4. **Browser Opening**: Platform-specific HTML report opening

---

## 📋 Original Features

A PowerShell script to audit privileged users in Microsoft Entra ID and Azure with detailed reporting

![need4adminv 1 0](https://github.com/user-attachments/assets/bac8b0e7-38ee-4fed-8bf5-ca933d487685)

### Report Includes
- UPN
- Entra Active Roles
- Entra Eligible Roles
- Azure Active Roles
- Azure Eligible Roles
- Total roles
- Account status (Active/Disabled)
- Account type (Cloud/Hybrid)
- MFA Status (YES/NO)
- Last interactive and non-interactive sign in date and time
- Authentication methods registered
- Total Users Without MFA
- Total Entra Active Roles
- Total Azure Active Roles
- Total Azure Eligible Roles
- Total Hybrid Users
- Total Users
- Total Active Users
- Total users with registered phishing resistant authentication methods
- Highlights Global admin and Owner roles with red text
- Highlights users without MFA with red text
- Highlights Hybrid users with yellow text
- Highlights Disabled status with red text
- Highlights Enabled users with green text
- Highlights users with MFA with green text
- Highlights Cloud users with blue text
- Highlights phishing resistant authentication methods
- Highlights if role is assigned via PIM group
- Search function in html report

### Features
- After script finishes running, it automatically opens an HTML Report in default browser
- HTML report columns are sortable and resizable
- Generates both .html and .csv files in a secure location outside the repository:
  - **Windows**: `%USERPROFILE%\Need4Admin-Reports\`
  - **macOS/Linux**: `$HOME/Need4Admin-Reports/`
- Reports are automatically excluded from Git to prevent accidental commit of sensitive data

---

## 🚀 Installation & Usage

### Prerequisites

#### All Platforms
- **PowerShell Core 7.0+** (recommended for macOS/Linux)
- Microsoft Graph PowerShell SDK
- Azure PowerShell modules (if scanning Azure roles)

#### macOS Installation
```bash
# Install PowerShell Core
brew install --cask powershell

# Launch PowerShell
pwsh

# Run the script
./Need4Admin_V1.0.ps1
```

#### Linux Installation
```bash
# Install PowerShell Core (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y powershell

# Or using Snap
sudo snap install powershell --classic

# Launch PowerShell
pwsh

# Run the script
./Need4Admin_V1.0.ps1
```

#### Windows
```powershell
# PowerShell 5.1+ or PowerShell Core 7.0+
.\Need4Admin_V1.0.ps1
```

### Running the Script

The script will automatically:
- Check for required AZ and Graph modules
- Install missing modules as CurrentUser if needed
- Prompt for Azure authentication (optional)
- Generate HTML and CSV reports

```bash
# Basic usage (interactive authentication)
pwsh ./Need4Admin_V1.0.ps1

# With service principal (certificate authentication)
pwsh ./Need4Admin_V1.0.ps1 -TenantId "your-tenant-id" -ClientId "your-app-id" -CertificateThumbprint "cert-thumbprint"
```

---

---

## 🐛 Troubleshooting

### macOS/Linux Specific Issues

#### Module Installation Fails
```bash
# Check PowerShell module path
pwsh -Command '$env:PSModulePath'

# Manually create module directory if needed
mkdir -p ~/.local/share/powershell/Modules
```

#### HTML Report Doesn't Open
- **macOS**: Ensure `open` command is available (default on macOS)
- **Linux**: Install `xdg-utils` package
  ```bash
  # Ubuntu/Debian
  sudo apt-get install xdg-utils

  # RHEL/CentOS/Fedora
  sudo yum install xdg-utils
  ```

#### Module Version Conflicts
The fork automatically handles version conflicts with fallback loading. If issues persist:
```bash
# Start fresh PowerShell session
pwsh
./Need4Admin_V1.0.ps1
```

### Windows Issues (Original Documentation)

Please remove all modules which script uses in Documents folder `WindowsPowerShell/Modules` (for version 5.1) or in `PowerShell` (for version 7+), empty recycle bin and re-run the script. If it doesn't help, please open an issue.

<img width="435" height="405" alt="image" src="https://github.com/user-attachments/assets/338a5d9f-e935-47de-8097-88609768ea12" />

---

## 🤝 Contributing

This is a fork focused on cross-platform compatibility. For core functionality changes, please contribute to the [original repository](https://github.com/vladjohansen/Need4Admin).

For macOS/Linux specific improvements:
1. Fork this repository
2. Create a feature branch
3. Submit a pull request

---

## 📜 License

This fork maintains the same license as the original project.

---

## 🙏 Credits

- **Original Author**: [Vlad Johansen](https://github.com/vladjohansen) - Created the excellent Need4Admin scanner
- **Fork Maintainer**: [pesip](https://github.com/pesip) - Cross-platform compatibility

---

## 📊 Version History

### v1.0-pesip.1 (2025-01-XX)
- ✅ Added macOS support
- ✅ Added Linux support
- ✅ Enhanced module loading with version conflict resolution
- ✅ Cross-platform HTML report opening
- ✅ Cleaner console output (suppressed assembly warnings)

### v1.0 (Original - Vlad Johansen)
- Initial Windows release with full Entra ID and Azure scanning capabilities