# Need4Admin - Privileged User Scanner (Beta)

A PowerShell script to audit privileged users in Microsoft Entra ID and Azure with detailed reporting
<img width="2207" height="1157" alt="Skjermbilde 2025-07-19 125129" src="https://github.com/user-attachments/assets/9894956a-fb30-45ed-b359-6eca45d9653c" />

## Report Includes
- UPN
- Entra Active Roles
- Entra Eligible Roles
- Azure Active Roles
- Azure Eligible Roles
- Total roles count
- Account status (Active/Disabled)
- Account type (Cloud/Hybrid)
- MFA Status (YES/NO)
- Last interactive and non-interactive sign in date and time
- Authentication methods registered

## Features
- After script finishes running, it automatically opens an HTML Report in default browser
- HTML report columns are sortable and resizable
- Generates both .html and .csv files in the script's folder

## Prerequisites
- PowerShell 5.1 or newer

The script will automatically:
- Check for required AZ and Graph modules
- Install missing modules as CurrentUser if needed

## Notes
- Beta version - please report any issues
