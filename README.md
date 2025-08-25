# Need4Admin - Privileged User Scanner (Beta)

A PowerShell script to audit privileged users in Microsoft Entra ID and Azure with detailed reporting

![GitHub all releases](https://img.shields.io/github/downloads/vladjoh/Need4Admin/total)

<img width="2222" height="1157" alt="git" src="https://github.com/user-attachments/assets/abbbfac2-7aee-411b-9b85-587218f47e4b" />

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
- Highlights Global admin and Owner roles with red text
- Highlights users without MFA with red text
- Highlights Hybrid users with yellow text
- Highlights Disabled status with red text
- Highlights Enabled users with green text
- Highlights users with MFA with green text
- Highlights Cloud users with blue text

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
