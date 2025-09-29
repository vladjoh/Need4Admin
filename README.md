# Need4Admin - Privileged User Scanner (Beta)

A PowerShell script to audit privileged users in Microsoft Entra ID and Azure with detailed reporting

![need4adminv 1 0](https://github.com/user-attachments/assets/bac8b0e7-38ee-4fed-8bf5-ca933d487685)


## Report Includes
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
