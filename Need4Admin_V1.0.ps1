<#PSScriptInfo

.VERSION 1.0

.GUID ade250cd-cc25-4cdd-8432-ad4c1d4561d3

.AUTHOR Vlad Johansen

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 A PowerShell script to audit privileged users in Microsoft Entra ID and Azure with detailed reporting 

#> 

<#
==================================================================================================
Name:           Need4Admin - Microsoft Privileged User Scanner
Description:    Privileged User Scanner Script for Entra and Azure
Version:        1.0
Author:         Vlad Johansen, 2025
==================================================================================================
#>

param(
    [string] $TenantId = "",
    [string] $ClientId = "",
    [string] $CertificateThumbprint = ""
)

# List of privileged roles to include
$PrivRoles = @{
    "Application Administrator" = $null
    "Application Developer" = $null
    "Attribute Provisioning Administrator" = $null
    "Authentication Administrator" = $null
    "Authentication Extensibility Administrator" = $null
    "B2C IEF Keyset Administrator" = $null
    "Billing Administrator" = $null
    "Cloud Application Administrator" = $null
    "Cloud Device Administrator" = $null
    "Compliance Administrator" = $null
    "Conditional Access Administrator" = $null
    "Directory Writers" = $null
    "Domain Name Administrator" = $null
    "Exchange Administrator" = $null
    "External Identity Provider Administrator" = $null
    "Global Administrator" = $null
    "Global Reader" = $null
    "Helpdesk Administrator" = $null
    "Hybrid Identity Administrator" = $null
    "Intune Administrator" = $null
    "Lifecycle Workflows Administrator" = $null
    "Password Administrator" = $null
    "Privileged Authentication Administrator" = $null
    "Privileged Role Administrator" = $null
    "Security Administrator" = $null
    "Security Operator" = $null
    "Security Reader" = $null
    "SharePoint Administrator" = $null
    "Teams Administrator" = $null
    "User Administrator" = $null
}

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "Need4Admin - Microsoft Privileged User Scanner" -ForegroundColor Yellow
Write-Host "Version 1.0" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# Required modules
$requiredModules = @{
    "Az.Accounts" = "2.12.0"
    "Az.Resources" = "6.0.0"
    "Microsoft.Graph.Authentication" = "2.15.0"
    "Microsoft.Graph.Users" = "2.15.0"
    "Microsoft.Graph.Groups" = "2.15.0"
    "Microsoft.Graph.Identity.DirectoryManagement" = "2.15.0"
    "Microsoft.Graph.Identity.SignIns" = "2.15.0"
    "Microsoft.Graph.Reports" = "2.15.0"
}

# Check for module availability
$missingModules = @()

# Ensure CurrentUser module path is included (cross-platform)
if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
    $env:PSModulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules;$env:PSModulePath"
} else {
    # macOS/Linux
    $env:PSModulePath = "$HOME/.local/share/powershell/Modules:$env:PSModulePath"
}

foreach ($modName in $requiredModules.Keys) {
    # Refresh of available modules
    Get-Module $modName -ListAvailable -Refresh | Out-Null
    $installedModule = Get-Module $modName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    
    if (-not $installedModule) {
        $missingModules += $modName
    }
}

if($missingModules.Count -gt 0) { 
    Write-Host "Important: Required modules are unavailable. The following modules need to be installed:" -ForegroundColor Red
    foreach ($mod in $missingModules) {
        Write-Host "  - $mod" -ForegroundColor Yellow
    }
    Write-Host ""
    $confirm = Read-Host "Are you sure you want to install the required modules? [Y] Yes [N] No"
    if($confirm -match "[yY]") { 
        Write-Host "Installing required modules..." -ForegroundColor Yellow
        
        # Set PSGallery as trusted
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        
        # Install only missing modules
        foreach ($modName in $missingModules) {
            Write-Host "Installing $modName..." -ForegroundColor Yellow
            try {
                Install-Module $modName -Scope CurrentUser -AllowClobber -Force -Confirm:$false -ErrorAction Stop
                Write-Host "  ✔ $modName installed successfully" -ForegroundColor Green
            } catch {
                Write-Host "  ✗ Failed to install $modName : $_" -ForegroundColor Red
                Exit
            }
        }
        Write-Host "Required modules installed successfully" -ForegroundColor Green
    } else { 
        Write-Host "Exiting. Required modules must be available." -ForegroundColor Red
        Exit 
    } 
}

# Import required modules
Write-Host "Loading modules..." -ForegroundColor Yellow

# Load Az modules first with MinimumVersion to avoid conflicts
$azModules = @("Az.Accounts", "Az.Resources")
foreach ($modName in $azModules) {
    if ($requiredModules.ContainsKey($modName)) {
        try {
            # Use MinimumVersion instead of RequiredVersion for flexibility
            Import-Module $modName -MinimumVersion $requiredModules[$modName] -Force -ErrorAction Stop -WarningAction SilentlyContinue
            Write-Host "  ✔ $modName loaded" -ForegroundColor Green
        } catch {
            # Try to import without version requirement as fallback
            try {
                Import-Module $modName -Force -ErrorAction Stop -WarningAction SilentlyContinue
                Write-Host "  ✔ $modName loaded (using available version)" -ForegroundColor Green
            } catch {
                Write-Host "  ✗ Failed to load $modName : $_" -ForegroundColor Red
                Exit
            }
        }
    }
}

# Then load Microsoft.Graph modules
$graphModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users", "Microsoft.Graph.Groups",
                  "Microsoft.Graph.Identity.DirectoryManagement", "Microsoft.Graph.Identity.SignIns",
                  "Microsoft.Graph.Reports")
foreach ($modName in $graphModules) {
    if ($requiredModules.ContainsKey($modName)) {
        try {
            Import-Module $modName -MinimumVersion $requiredModules[$modName] -Force -ErrorAction Stop -WarningAction SilentlyContinue
            Write-Host "  ✔ $modName loaded" -ForegroundColor Green
        } catch {
            # Try to import without version requirement as fallback
            try {
                Import-Module $modName -Force -ErrorAction Stop -WarningAction SilentlyContinue
                Write-Host "  ✔ $modName loaded (using available version)" -ForegroundColor Green
            } catch {
                Write-Host "  ✗ Failed to load $modName : $_" -ForegroundColor Red
                Exit
            }
        }
    }
}

# Load required assembly for URL encoding
Add-Type -AssemblyName System.Web

# Connect to Microsoft Graph 
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
if (![string]::IsNullOrEmpty($TenantId) -and ![string]::IsNullOrEmpty($ClientId) -and ![string]::IsNullOrEmpty($CertificateThumbprint)) {  
    Connect-MgGraph -TenantId $TenantId -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -ErrorAction SilentlyContinue -ErrorVariable ConnectionError | Out-Null
    if ($null -ne $ConnectionError -and $ConnectionError.Count -gt 0) {    
        Write-Host $ConnectionError -Foregroundcolor Red
        Exit
    }
} else {
    Connect-MgGraph -Scopes @(
        "Directory.Read.All",
        "User.Read.All", 
        "UserAuthenticationMethod.Read.All",
        "RoleManagement.Read.Directory",
        "RoleManagement.Read.All",
        "RoleEligibilitySchedule.Read.Directory",
        "RoleAssignmentSchedule.Read.Directory",
        "AuditLog.Read.All",
        "Reports.Read.All",
        "Group.Read.All"
    ) -ErrorAction SilentlyContinue -ErrorVariable ConnectionError | Out-Null
    if ($null -ne $ConnectionError -and $ConnectionError.Count -gt 0) {
        Write-Host "Connection failed: $ConnectionError" -ForegroundColor Red
        Exit
    }
}

Write-Host "Microsoft Graph PowerShell module is connected successfully" -ForegroundColor Green

# Get the authenticated context for Azure connection
$context = Get-MgContext
$currentTenantId = $context.TenantId

# ASK USER IF THEY WANT TO CONNECT TO AZURE
Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Azure Role Scanning Option" -ForegroundColor Yellow
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Do you want to scan Azure roles?" -ForegroundColor Yellow
Write-Host "Note: This requires Azure subscription access" -ForegroundColor Gray
Write-Host ""
$azureChoice = Read-Host "Connect to Azure? [Y] Yes [N] No (Entra ID only)"

$azureConnected = $false
if ($azureChoice -match "[yY]") {
    Write-Host ""
    Write-Host "Connecting to Azure..." -ForegroundColor Yellow
    try {
        if (![string]::IsNullOrEmpty($ClientId) -and ![string]::IsNullOrEmpty($CertificateThumbprint)) {
            # Use the tenant ID from context if not provided as parameter
            $azureTenantId = if (![string]::IsNullOrEmpty($TenantId)) { $TenantId } else { $currentTenantId }
            Connect-AzAccount -TenantId $azureTenantId -ApplicationId $ClientId -CertificateThumbprint $CertificateThumbprint -ServicePrincipal -ErrorAction Stop | Out-Null
        } else {
            # For interactive login, specify tenant if available
            if (![string]::IsNullOrEmpty($currentTenantId)) {
                Connect-AzAccount -TenantId $currentTenantId -ErrorAction Stop | Out-Null
            } else {
                Connect-AzAccount -ErrorAction Stop | Out-Null
            }
        }
        Write-Host "Azure PowerShell module is connected successfully" -ForegroundColor Green
        $azureConnected = $true
    } catch {
        Write-Host "Azure connection failed: $_" -ForegroundColor Yellow
        Write-Host "Continuing with Entra ID only..." -ForegroundColor Yellow
        $azureConnected = $false
    }
} else {
    Write-Host ""
    Write-Host "Skipping Azure authentication - will scan Entra ID roles only" -ForegroundColor Yellow
    $azureConnected = $false
}

Write-Host ""

# Use new API endpoint to get auth. methods
function Get-MFAInfo {
    param($userId)
    
    $authMethodsFormatted = @()
    $hasMFA = $false
    $hasPhishingResistant = $false
    
    try {
        # Use beta endpoint
        $uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails('$userId')"
        $userAuthDetails = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
        
        if ($userAuthDetails.methodsRegistered) {
            foreach ($method in $userAuthDetails.methodsRegistered) {
                $formattedMethod = switch ($method) {
                    "password" { "password" }
                    "email" { "email" }
                    "mobilePhone" { "mobilePhone" }
                    "alternateMobilePhone" { "alternateMobilePhone" }
                    "officePhone" { "officePhone" }
                    "microsoftAuthenticatorPush" { "microsoftAuthenticatorPush" }
                    "softwareOneTimePasscode" { "softwareOneTimePasscode" }
                    "hardwareOneTimePasscode" { "hardwareOneTimePasscode" }
                    "microsoftAuthenticatorPasswordless" { 
                        "microsoftAuthenticatorPasswordless"
                    }
                    "windowsHelloForBusiness" { 
                        $hasPhishingResistant = $true
                        "windowsHelloForBusiness"
                    }
                    "fido2SecurityKey" { 
                        $hasPhishingResistant = $true
                        "fido2SecurityKey"
                    }
                    "temporaryAccessPass" { "temporaryAccessPass" }
                    "securityQuestion" { "securityQuestion" }
                    "macOsSecureEnclaveKey" { 
                        "macOsSecureEnclaveKey"
                    }
                    "passkeyDeviceBound" { 
                        $hasPhishingResistant = $true
                        "passkeyDeviceBound"
                    }
                    "passkeyDeviceBoundAuthenticator" { 
                        $hasPhishingResistant = $true
                        "passkeyDeviceBoundAuthenticator"
                    }
                    "passkeyDeviceBoundWindowsHello" { 
                        $hasPhishingResistant = $true
                        "passkeyDeviceBoundWindowsHello"
                    }
                    "externalAuthenticator" { "externalAuthenticator" }
                    default { $method }
                }
                
                $authMethodsFormatted += $formattedMethod
                
                # Check if it's an MFA method (not just password or email)
                if ($method -ne "password" -and $method -ne "email") {
                    $hasMFA = $true
                }
            }
        }
        
        if ($authMethodsFormatted.Count -eq 0) { 
            $authMethodsFormatted = @("None") 
        }
    } catch {
        $authMethodsFormatted = @("Unable to check")
        $hasMFA = $false
    }
    
    return @{
        Methods = ($authMethodsFormatted | Select-Object -Unique) -join ", "
        HasMFA = if ($hasMFA) { "Yes" } else { "No" }
        HasPhishingResistant = $hasPhishingResistant
    }
}

# Get-EligibleRoles function to return role names with group indicator
function Get-EligibleRoles {
    param($userId)
    
    try {
        $eligibleRoles = @()
        
        # Direct role assignments for the user
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$userId'&`$expand=roleDefinition"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
        
        if ($response.value) {
            foreach ($item in $response.value) {
                if ($item.status -eq "Provisioned" -and $item.roleDefinition -and $item.roleDefinition.displayName) {
                    $eligibleRoles += $item.roleDefinition.displayName
                }
            }
        }
        
        # Get all user's groups
        $userGroups = Get-MgUserMemberOf -UserId $userId -All -ErrorAction SilentlyContinue
        $userGroupIds = @()
        
        foreach ($group in $userGroups) {
            if ($group.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') {
                $userGroupIds += $group.Id
            }
        }
        
        # Check if ANY of user's groups have PIM eligible roles
        foreach ($groupId in $userGroupIds) {
            $groupUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$groupId'&`$expand=roleDefinition"
            $groupResponse = Invoke-MgGraphRequest -Uri $groupUri -Method GET -ErrorAction SilentlyContinue
            
            if ($groupResponse.value) {
                foreach ($item in $groupResponse.value) {
                    if ($item.status -eq "Provisioned" -and $item.roleDefinition -and $item.roleDefinition.displayName) {
                        # Check if it's a privileged role
                        if ($PrivRoles.ContainsKey($item.roleDefinition.displayName)) {
                            $roleName = $item.roleDefinition.displayName + " (via group)"
                            $eligibleRoles += $roleName
                        }
                    }
                }
            }
        }
        
        # Remove duplicates and sort
        $eligibleRoles = $eligibleRoles | Where-Object { $_ -ne $null -and $_ -ne "" } | Sort-Object -Unique
        
        return $eligibleRoles
    } catch {
        Write-Warning "Error fetching eligible roles for user $userId : $_"
        return @()
    }
}

# Get-AzureRoleAssignments function to include group indicators
function Get-AzureRoleAssignments {
    param($userObjectId)
    
    if (-not $azureConnected) {
        return @{
            ActiveRoles = @()
            EligibleRoles = @()
        }
    }
    
    $activeRoles = @()
    $eligibleRoles = @()
    
    try {
        # Get all subscriptions the user has access to
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
        
        # Get user's group memberships for group-based checks
        $userGroups = @()
        try {
            $groups = Get-MgUserMemberOf -UserId $userObjectId -All -ErrorAction SilentlyContinue
            foreach ($group in $groups) {
                if ($group.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') {
                    $userGroups += $group.Id
                }
            }
        } catch {
            Write-Verbose "Failed to get user groups: $_"
        }
        
        foreach ($subscription in $subscriptions) {
            try {
                Set-AzContext -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue | Out-Null
                
                # Get active role assignments for this user in the subscription
                $roleAssignments = Get-AzRoleAssignment -ObjectId $userObjectId -ErrorAction SilentlyContinue
                
                foreach ($assignment in $roleAssignments) {
                    # Include privileged roles
                    $isPrivilegedRole = $assignment.RoleDefinitionName -eq "Owner" -or 
                                       $assignment.RoleDefinitionName -like "*Contributor" -or
                                       $assignment.RoleDefinitionName -eq "Reservations Administrator" -or
                                       $assignment.RoleDefinitionName -eq "Role Based Access Control Administrator" -or
                                       $assignment.RoleDefinitionName -eq "User Access Administrator"
                    
                    if ($isPrivilegedRole) {
                        $scopeInfo = ""
                        
                        if ($assignment.Scope -eq "/subscriptions/$($subscription.Id)") {
                            $scopeInfo = "Sub: $($subscription.Name)"
                        } elseif ($assignment.Scope -match "/subscriptions/.+/resourceGroups/([^/]+)$") {
                            $rgName = $matches[1]
                            $scopeInfo = "RG: $rgName (Sub: $($subscription.Name))"
                        } else {
                            $resourceName = ($assignment.Scope -split "/")[-1]
                            if ($assignment.Scope -match "/subscriptions/.+/resourceGroups/([^/]+)/") {
                                $rgName = $matches[1]
                                $scopeInfo = "Resource: $resourceName (RG: $rgName, Sub: $($subscription.Name))"
                            } else {
                                $scopeInfo = "Resource: $resourceName (Sub: $($subscription.Name))"
                            }
                        }
                        
                        $activeRoles += "$($assignment.RoleDefinitionName) → $scopeInfo"
                    }
                }
                
                # Check for group-based active assignments
                foreach ($groupId in $userGroups) {
                    $groupAssignments = Get-AzRoleAssignment -ObjectId $groupId -ErrorAction SilentlyContinue
                    
                    if ($groupAssignments) {
                        foreach ($assignment in $groupAssignments) {
                            $isPrivilegedRole = $assignment.RoleDefinitionName -eq "Owner" -or 
                                               $assignment.RoleDefinitionName -like "*Contributor" -or
                                               $assignment.RoleDefinitionName -eq "Reservations Administrator" -or
                                               $assignment.RoleDefinitionName -eq "Role Based Access Control Administrator" -or
                                               $assignment.RoleDefinitionName -eq "User Access Administrator"
                            
                            if ($isPrivilegedRole) {
                                $scopeInfo = ""
                                
                                if ($assignment.Scope -eq "/subscriptions/$($subscription.Id)") {
                                    $scopeInfo = "Sub: $($subscription.Name)"
                                } elseif ($assignment.Scope -match "/subscriptions/.+/resourceGroups/([^/]+)$") {
                                    $rgName = $matches[1]
                                    $scopeInfo = "RG: $rgName (Sub: $($subscription.Name))"
                                } else {
                                    $resourceName = ($assignment.Scope -split "/")[-1]
                                    if ($assignment.Scope -match "/subscriptions/.+/resourceGroups/([^/]+)/") {
                                        $rgName = $matches[1]
                                        $scopeInfo = "Resource: $resourceName (RG: $rgName, Sub: $($subscription.Name))"
                                    } else {
                                        $scopeInfo = "Resource: $resourceName (Sub: $($subscription.Name))"
                                    }
                                }
                                
                                $activeRoles += "$($assignment.RoleDefinitionName) → $scopeInfo (via group)"
                            }
                        }
                    }
                }
                
                # Get Azure PIM eligible assignments
                try {
                    $azContext = Get-AzContext
                    $azureToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                        $azContext.Account, 
                        $azContext.Environment, 
                        $azContext.Tenant.Id, 
                        $null, 
                        "Never", 
                        $null, 
                        "https://management.azure.com/"
                    ).AccessToken
                    
                    if ($azureToken) {
                        $headers = @{
                            'Authorization' = "Bearer $azureToken"
                            'Content-Type' = 'application/json'
                        }
                        
                        # Direct Azure PIM user assignments 
                        $pimUri = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&`$filter=principalId eq '$userObjectId'"
                        $pimResponse = Invoke-RestMethod -Uri $pimUri -Headers $headers -Method GET -ErrorAction SilentlyContinue
                        
                        if ($pimResponse.value) {
                            foreach ($eligibleAssignment in $pimResponse.value) {
                                # Get role definition name
                                $roleDefId = $eligibleAssignment.properties.roleDefinitionId
                                $roleDefUri = "https://management.azure.com$($roleDefId)?api-version=2022-04-01"
                                $roleDefResponse = Invoke-RestMethod -Uri $roleDefUri -Headers $headers -Method GET -ErrorAction SilentlyContinue
                                
                                if ($roleDefResponse) {
                                    $roleDefName = $roleDefResponse.properties.roleName
                                    
                                    # Check if it's a privileged role
                                    $isPrivilegedRole = $roleDefName -eq "Owner" -or 
                                                       $roleDefName -like "*Contributor" -or
                                                       $roleDefName -eq "Reservations Administrator" -or
                                                       $roleDefName -eq "Role Based Access Control Administrator" -or
                                                       $roleDefName -eq "User Access Administrator"
                                    
                                    if ($isPrivilegedRole) {
                                        $scope = $eligibleAssignment.properties.scope
                                        $scopeInfo = ""
                                        
                                        if ($scope -eq "/subscriptions/$($subscription.Id)") {
                                            $scopeInfo = "$roleDefName → Subscription ($($subscription.Name))"
                                        } elseif ($scope -match "/subscriptions/.+/resourceGroups/([^/]+)$") {
                                            $rgName = $matches[1]
                                            $scopeInfo = "$roleDefName → Resource Group ($rgName)"
                                        } else {
                                            $resourceName = ($scope -split "/")[-1]
                                            $scopeInfo = "$roleDefName → Resource ($resourceName)"
                                        }
                                        
                                        if ($eligibleRoles -notcontains $scopeInfo) {
                                            $eligibleRoles += $scopeInfo
                                        }
                                    }
                                }
                            }
                        }
                        
                        # Group-based eligible assignments
                        foreach ($groupId in $userGroups) {
                            $groupPimUri = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&`$filter=principalId eq '$groupId'"
                            $groupPimResponse = Invoke-RestMethod -Uri $groupPimUri -Headers $headers -Method GET -ErrorAction SilentlyContinue
                            
                            if ($groupPimResponse.value) {
                                foreach ($eligibleAssignment in $groupPimResponse.value) {
                                    # Get role definition name
                                    $roleDefId = $eligibleAssignment.properties.roleDefinitionId
                                    $roleDefUri = "https://management.azure.com$($roleDefId)?api-version=2022-04-01"
                                    $roleDefResponse = Invoke-RestMethod -Uri $roleDefUri -Headers $headers -Method GET -ErrorAction SilentlyContinue
                                    
                                    if ($roleDefResponse) {
                                        $roleDefName = $roleDefResponse.properties.roleName
                                        
                                        # Check if it's a privileged role
                                        $isPrivilegedRole = $roleDefName -eq "Owner" -or 
                                                           $roleDefName -like "*Contributor" -or
                                                           $roleDefName -eq "Reservations Administrator" -or
                                                           $roleDefName -eq "Role Based Access Control Administrator" -or
                                                           $roleDefName -eq "User Access Administrator"
                                        
                                        if ($isPrivilegedRole) {
                                            $scope = $eligibleAssignment.properties.scope
                                            $scopeInfo = ""
                                            
                                            if ($scope -eq "/subscriptions/$($subscription.Id)") {
                                                $scopeInfo = "$roleDefName → Subscription ($($subscription.Name)) (via group)"
                                            } elseif ($scope -match "/subscriptions/.+/resourceGroups/([^/]+)$") {
                                                $rgName = $matches[1]
                                                $scopeInfo = "$roleDefName → Resource Group ($rgName) (via group)"
                                            } else {
                                                $resourceName = ($scope -split "/")[-1]
                                                $scopeInfo = "$roleDefName → Resource ($resourceName) (via group)"
                                            }
                                            
                                            if ($eligibleRoles -notcontains $scopeInfo) {
                                                $eligibleRoles += $scopeInfo
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-Verbose "Failed to get PIM eligible roles for subscription $($subscription.Name): $_"
                }
                
            } catch {
                Write-Verbose "Failed to process subscription $($subscription.Name): $_"
                continue
            }
        }
        
    } catch {
        Write-Verbose "Failed to get Azure role assignments for user $userObjectId : $_"
    }
    
    return @{
        ActiveRoles = $activeRoles | Sort-Object -Unique
        EligibleRoles = $eligibleRoles | Sort-Object -Unique
    }
}

function Get-UserType {
    param($user)
    try {
        # Check if user is synced from on-premises (hybrid)
        if ($user.OnPremisesSyncEnabled -eq $true) {
            return "Hybrid"
        } 
        # Check if user has on-premises attributes (additional hybrid check)
        elseif (![string]::IsNullOrEmpty($user.OnPremisesSecurityIdentifier) -or 
                ![string]::IsNullOrEmpty($user.OnPremisesSamAccountName) -or
                ![string]::IsNullOrEmpty($user.OnPremisesUserPrincipalName)) {
            return "Hybrid"
        }
        # Pure cloud user
        else {
            return "Cloud"
        }
    } catch {
        return "Unknown"
    }
}

Write-Host "Scanning users for admin roles..." -ForegroundColor Yellow
$privilegedUsers = @()

# Get all directory roles first
$roles = Get-MgDirectoryRole -All -ErrorAction SilentlyContinue
if (-not $roles) {
    Write-Host "Unable to retrieve directory roles. Please check your permissions." -ForegroundColor Red
    Exit
}

$relevantRoles = $roles | Where-Object { $_.DisplayName -and $PrivRoles.ContainsKey($_.DisplayName) }

if ($relevantRoles.Count -eq 0) {
    Write-Host "No privileged roles found" -ForegroundColor Red
    Exit
}

# Collect all unique user IDs with their roles
$userRolesMap = @{}
$totalRoles = $relevantRoles.Count
$currentRole = 0

# Process active roles and eligible roles together for efficiency
Write-Progress -Activity "Scanning users for admin roles" -Status "Processing privileged roles..." -PercentComplete 0

# Create global group cache 
$global:GroupNameCache = @{}

foreach ($role in $relevantRoles) {
    $currentRole++
    Write-Progress -Activity "Scanning users for admin roles" -Status "Processing $($role.DisplayName) ($currentRole/$totalRoles)" -PercentComplete (($currentRole / $totalRoles) * 100)
    
    # Get all members of this role (direct assignments)
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
    
    foreach ($member in $members) {
        if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
            $userId = $member.Id
            if (-not $userRolesMap.ContainsKey($userId)) {
                $userRolesMap[$userId] = [System.Collections.ArrayList]::new()
            }
            $null = $userRolesMap[$userId].Add($role.DisplayName)
        }
        # Check if it's a group assignment
        elseif ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') {
            $groupId = $member.Id
            
            # Get members of the group 
            try {
                $groupMembers = Get-MgGroupMember -GroupId $groupId -All -ErrorAction Stop
                foreach ($groupMember in $groupMembers) {
                    if ($groupMember.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                        $userId = $groupMember.Id
                        if (-not $userRolesMap.ContainsKey($userId)) {
                            $userRolesMap[$userId] = [System.Collections.ArrayList]::new()
                        }
                        # Check if this role is already added for this user to avoid duplicates
                        $roleWithGroup = "$($role.DisplayName) (via group)"
                        if (-not $userRolesMap[$userId].Contains($roleWithGroup) -and -not $userRolesMap[$userId].Contains($role.DisplayName)) {
                            $null = $userRolesMap[$userId].Add($roleWithGroup)
                        }
                    }
                }
            } catch {
                Write-Warning "Failed to get members for group $groupId : $_"
            }
        }
    }
}

# Quickly check for users with only eligible roles (combine with role scanning)
try {
    Write-Progress -Activity "Scanning users for admin roles" -Status "Checking eligible role assignments..." -PercentComplete 90
    
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$expand=roleDefinition&`$top=500"
    $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
    
    if ($response.value) {
        foreach ($item in $response.value) {
            if ($item.status -eq "Provisioned" -and 
                $item.roleDefinition -and 
                $item.roleDefinition.displayName -and
                $PrivRoles.ContainsKey($item.roleDefinition.displayName)) {
                
                $userId = $item.principalId
                if (-not $userRolesMap.ContainsKey($userId)) {
                    $userRolesMap[$userId] = [System.Collections.ArrayList]::new()
                }
            }
        }
    }
} catch {
    Write-Verbose "Failed to retrieve eligible role assignments quickly"
}

Write-Progress -Activity "Scanning users for admin roles" -Completed

# Process users
$userIds = @($userRolesMap.Keys)
$totalUsers = $userIds.Count

if ($totalUsers -eq 0) {
    Write-Host "No privileged users found" -ForegroundColor Red
    Exit
}

Write-Host "Found $totalUsers users" -ForegroundColor Green
Write-Host "Processing user details..." -ForegroundColor Yellow

$processedCount = 0

foreach ($userId in $userIds) {
    $processedCount++
    Write-Progress -Activity "Processing users" -Status "User $processedCount of $totalUsers" -PercentComplete (($processedCount / $totalUsers) * 100)
    
    try {
        # Get user with FULL properties including SignInActivity 
        $user = Get-MgUser -UserId $userId -Property "Id,UserPrincipalName,DisplayName,AccountEnabled,Mail,OnPremisesSyncEnabled,OnPremisesSecurityIdentifier,OnPremisesSamAccountName,OnPremisesUserPrincipalName,OnPremisesImmutableId,SignInActivity" -ErrorAction Stop
        
        # Get sign-in data DIRECTLY from SignInActivity property only for faster processing 
        $interactiveSignIn = "Never"
        $nonInteractiveSignIn = "Never"
        
        if ($user.SignInActivity) {
            if ($user.SignInActivity.LastSignInDateTime) {
                try {
                    $interactiveSignIn = ([DateTime]$user.SignInActivity.LastSignInDateTime).ToString("yyyy-MM-dd HH:mm")
                } catch {
                    $interactiveSignIn = "Never"
                }
            }
            if ($user.SignInActivity.LastNonInteractiveSignInDateTime) {
                try {
                    $nonInteractiveSignIn = ([DateTime]$user.SignInActivity.LastNonInteractiveSignInDateTime).ToString("yyyy-MM-dd HH:mm")
                } catch {
                    $nonInteractiveSignIn = "Never"
                }
            }
        }
        
        $userRoles = $userRolesMap[$userId]
        $eligibleRoles = Get-EligibleRoles -userId $userId
        $userType = Get-UserType -user $user
        
        # Get Azure role assignments
        $azureRoles = Get-AzureRoleAssignments -userObjectId $userId
        
        # Get MFA info
        $authMethods = Get-MFAInfo -userId $userId
        
        # Format roles for display
        $entraActiveRolesDisplay = if ($userRoles.Count -gt 0) {
            ($userRoles | Sort-Object) -join "; "
        } else {
            "None"
        }
        
        $entraEligibleRolesDisplay = if ($eligibleRoles.Count -gt 0) {
            ($eligibleRoles | Sort-Object) -join "; "
        } else {
            "None"
        }
        
        # Format Azure roles for display
        $azActiveRolesDisplay = if ($azureRoles.ActiveRoles.Count -gt 0) {
            $sortedRoles = $azureRoles.ActiveRoles | Sort-Object { if ($_ -like "*Owner*") { "0" } else { "1" + $_ } }
            ($sortedRoles -join "; ")
        } else {
            "None"
        }
        
        $azEligibleRolesDisplay = if ($azureRoles.EligibleRoles.Count -gt 0) {
            $sortedRoles = $azureRoles.EligibleRoles | Sort-Object { if ($_ -like "*Owner*") { "0" } else { "1" + $_ } }
            ($sortedRoles -join "; ")
        } else {
            "None"
        }
        
        $privilegedUsers += [PSCustomObject]@{
            'UPN' = $user.UserPrincipalName
            'Entra Active Roles' = $entraActiveRolesDisplay
            'Entra Eligible Roles' = $entraEligibleRolesDisplay
            'Azure Active Roles' = $azActiveRolesDisplay
            'Azure Eligible Roles' = $azEligibleRolesDisplay
            'Total Roles' = $userRoles.Count + $eligibleRoles.Count + $azureRoles.ActiveRoles.Count + $azureRoles.EligibleRoles.Count
            'Account Status' = if ($user.AccountEnabled) { "Active" } else { "Disabled" }
            'User Type' = $userType
            'MFA Enabled' = $authMethods.HasMFA
            'Last Interactive Sign In' = $interactiveSignIn
            'Last Non-Interactive Sign In' = $nonInteractiveSignIn
            'Auth Methods' = $authMethods.Methods
            'HasPhishingResistant' = $authMethods.HasPhishingResistant
            'Is Global Admin' = if (($userRoles | Sort-Object) -contains "Global Administrator" -or ($userRoles | Sort-Object) -contains "Global Administrator (via group)") { $true } else { $false }
        }
    } catch {
        Write-Warning "Failed to process user $userId : $_"
    }
}

Write-Progress -Activity "Processing users" -Completed

# Get context info for report
$context = Get-MgContext
$reportTenantId = $context.TenantId
$signedInUser = $context.Account

# Calculate summary statistics
$totalUsers = $privilegedUsers.Count
$activeUsers = ($privilegedUsers | Where-Object { $_.'Account Status' -eq 'Active' }).Count
$hybridUsers = ($privilegedUsers | Where-Object { $_.'User Type' -eq 'Hybrid' }).Count

# Count total roles
$entraActiveRolesCount = 0
$entraEligibleRolesCount = 0
$azureActiveRolesCount = 0
$azureEligibleRolesCount = 0

foreach ($user in $privilegedUsers) {
    # Count Entra roles
    if ($user.'Entra Active Roles' -ne 'None') {
        $entraActiveRolesCount += ($user.'Entra Active Roles' -split '; ').Count
    }
    if ($user.'Entra Eligible Roles' -ne 'None') {
        $entraEligibleRolesCount += ($user.'Entra Eligible Roles' -split '; ').Count
    }
    
    # Count Azure roles
    if ($user.'Azure Active Roles' -ne 'None') {
        $azureActiveRolesCount += ($user.'Azure Active Roles' -split '; ').Count
    }
    if ($user.'Azure Eligible Roles' -ne 'None') {
        $azureEligibleRolesCount += ($user.'Azure Eligible Roles' -split '; ').Count
    }
}

$usersWithoutMFA = ($privilegedUsers | Where-Object { $_.'MFA Enabled' -eq 'No' }).Count
$usersWithPhishingResistant = ($privilegedUsers | Where-Object { $_.HasPhishingResistant -eq $true }).Count

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "SCAN COMPLETED" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Total Privileged Users: $totalUsers" -ForegroundColor Yellow
Write-Host "Active Users: $activeUsers" -ForegroundColor Yellow
Write-Host "Hybrid Users: $hybridUsers" -ForegroundColor Yellow
Write-Host "Entra Active Roles Count: $entraActiveRolesCount" -ForegroundColor Yellow
Write-Host "Entra Eligible Roles Count: $entraEligibleRolesCount" -ForegroundColor Yellow
if ($azureConnected) {
    Write-Host "Azure Active Roles Count: $azureActiveRolesCount" -ForegroundColor Magenta
    Write-Host "Azure Eligible Roles Count: $azureEligibleRolesCount" -ForegroundColor Magenta
} else {
    Write-Host "Azure Roles: Not scanned (no Azure connection)" -ForegroundColor Gray
}
Write-Host "Users without MFA: $usersWithoutMFA" -ForegroundColor Yellow
Write-Host "Users with Phishing-Resistant Auth: $usersWithPhishingResistant" -ForegroundColor Green
Write-Host "Tenant ID: $reportTenantId" -ForegroundColor Yellow
Write-Host "Signed in as: $signedInUser" -ForegroundColor Yellow
Write-Host ""

# Save CSV file
$csvPath = ".\Need4Admin-Export-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').csv"
$privilegedUsers | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "CSV data saved as: $csvPath" -ForegroundColor Green

# Generate HTML report with search functionality
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Build the complete HTML string
$htmlReport = "<!DOCTYPE html>`n<html>`n<head>`n<title>Need4Admin - Privileged Users Report</title>`n"
$htmlReport += "<style>`n"
$htmlReport += "body{font-family:'Segoe UI',Arial,sans-serif;margin:20px;background-color:#f5f5f5;color:#333;}`n"
$htmlReport += ".header{background-color:#0078d4;color:white;padding:20px;border-radius:5px;margin-bottom:20px;}`n"
$htmlReport += ".summary{background-color:white;padding:15px;border-radius:5px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}`n"
$htmlReport += ".summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;}`n"
$htmlReport += ".summary-item{text-align:center;padding:10px;background-color:#f8f9fa;border-radius:3px;}`n"
$htmlReport += ".summary-number{font-size:24px;font-weight:bold;color:#0078d4;}.summary-label{font-size:12px;color:#666;margin-top:5px;}`n"
$htmlReport += ".azure-summary{color:#ff6600;}.phishing-resistant{color:#28a745;}`n"
# Add search bar styles
$htmlReport += ".search-container{background-color:white;padding:15px;border-radius:5px;margin-bottom:20px;box-shadow:0 2px 4px rgba(0,0,0,0.1);}`n"
$htmlReport += ".search-box{width:100%;padding:10px;border:1px solid #ddd;border-radius:4px;font-size:14px;box-sizing:border-box;}`n"
$htmlReport += ".search-box:focus{outline:none;border-color:#0078d4;box-shadow:0 0 0 2px rgba(0,120,212,0.1);}`n"
$htmlReport += ".search-info{margin-top:10px;font-size:12px;color:#666;}`n"
$htmlReport += "table{width:100%;border-collapse:collapse;background-color:white;border-radius:5px;overflow:hidden;box-shadow:0 2px 4px rgba(0,0,0,0.1);font-size:13px;}`n"
$htmlReport += "th{background-color:#f8f9fa;padding:10px 8px;text-align:left;font-weight:600;border-bottom:2px solid #dee2e6;cursor:pointer;user-select:none;}`n"
$htmlReport += "th:hover{background-color:#e9ecef;}`n"
$htmlReport += "td{padding:8px;border-bottom:1px solid #dee2e6;vertical-align:top;}`n"
$htmlReport += "tr:hover{background-color:#f8f9fa;}`n"
$htmlReport += "tr.hidden{display:none;}`n"
$htmlReport += ".status-active{color:#28a745;font-weight:bold;}.status-disabled{color:#dc3545;font-weight:bold;}`n"
$htmlReport += ".type-hybrid{color:#fd7e14;font-weight:bold;}.type-cloud{color:#0078d4;font-weight:bold;}`n"
$htmlReport += ".mfa-yes{color:#28a745;font-weight:bold;}.mfa-no{color:#dc3545;font-weight:bold;}`n"
$htmlReport += ".auth-method-phishing-resistant{color:#28a745;font-weight:bold;}`n"
$htmlReport += ".via-group{color:#0078d4;font-weight:bold;}`n"  # Changed from gray italic to blue bold
$htmlReport += ".footer{margin-top:20px;text-align:center;color:#666;font-size:12px;}`n"
$htmlReport += ".scroll-container{overflow-x:auto;}`n"
$htmlReport += ".sortable th::after{content:' ↕';color:#aaa;font-size:10px;}`n"
$htmlReport += "</style>`n</head>`n<body>`n"

# Add header
$htmlReport += "<div class='header'>`n<h1>Need4Admin - Privileged Users Report</h1>`n"
$htmlReport += "<p>Generated on: $timestamp | Tenant: $reportTenantId | Signed in as: $signedInUser</p>`n</div>`n"

# Add summary
$htmlReport += "<div class='summary'><div class='summary-grid'>`n"
$htmlReport += "<div class='summary-item'><div class='summary-number'>$totalUsers</div><div class='summary-label'>Total Users</div></div>`n"
$htmlReport += "<div class='summary-item'><div class='summary-number'>$activeUsers</div><div class='summary-label'>Active Users</div></div>`n"
$htmlReport += "<div class='summary-item'><div class='summary-number'>$hybridUsers</div><div class='summary-label'>Hybrid Users</div></div>`n"
$htmlReport += "<div class='summary-item'><div class='summary-number'>$entraActiveRolesCount</div><div class='summary-label'>Entra Active Roles</div></div>`n"
$htmlReport += "<div class='summary-item'><div class='summary-number'>$entraEligibleRolesCount</div><div class='summary-label'>Entra Eligible Roles</div></div>`n"
$htmlReport += "<div class='summary-item'><div class='summary-number azure-summary'>$azureActiveRolesCount</div><div class='summary-label'>Azure Active Roles</div></div>`n"
$htmlReport += "<div class='summary-item'><div class='summary-number azure-summary'>$azureEligibleRolesCount</div><div class='summary-label'>Azure Eligible Roles</div></div>`n"
$htmlReport += "<div class='summary-item'><div class='summary-number'>$usersWithoutMFA</div><div class='summary-label'>Without MFA</div></div>`n"
$htmlReport += "<div class='summary-item'><div class='summary-number phishing-resistant'>$usersWithPhishingResistant</div><div class='summary-label'>Phishing-Resistant Auth</div></div>`n"
$htmlReport += "</div></div>`n"

# Add search bar
$htmlReport += "<div class='search-container'>`n"
$htmlReport += "<input type='text' id='searchBox' class='search-box' placeholder='Search users, roles, status... (e.g., Global Administrator, via group, Active, No MFA)'>`n"
$htmlReport += "<div class='search-info' id='searchInfo'>Showing all $totalUsers users</div>`n"
$htmlReport += "</div>`n"

# Add table
$htmlReport += "<div class='scroll-container'>`n<table class='sortable' id='dataTable'>`n<thead>`n<tr>`n"
$htmlReport += "<th onclick='sortTable(0)'>UPN</th>`n"
$htmlReport += "<th onclick='sortTable(1)'>Entra Active Roles</th>`n"
$htmlReport += "<th onclick='sortTable(2)'>Entra Eligible Roles</th>`n"
$htmlReport += "<th onclick='sortTable(3)'>Azure Active Roles</th>`n"
$htmlReport += "<th onclick='sortTable(4)'>Azure Eligible Roles</th>`n"
$htmlReport += "<th onclick='sortTable(5)'>Total</th>`n"
$htmlReport += "<th onclick='sortTable(6)'>Status</th>`n"
$htmlReport += "<th onclick='sortTable(7)'>Type</th>`n"
$htmlReport += "<th onclick='sortTable(8)'>MFA</th>`n"
$htmlReport += "<th onclick='sortTable(9)'>Last Interactive Sign In</th>`n"
$htmlReport += "<th onclick='sortTable(10)'>Last Non-Interactive Sign In</th>`n"
$htmlReport += "<th onclick='sortTable(11)'>Auth Methods</th>`n"
$htmlReport += "</tr>`n</thead>`n<tbody>`n"

# Add table rows
foreach ($user in $privilegedUsers) {
    $statusClass = if ($user.'Account Status' -eq 'Active') { 'status-active' } else { 'status-disabled' }
    $typeClass = if ($user.'User Type' -eq 'Hybrid') { 'type-hybrid' } else { 'type-cloud' }
    $mfaClass = if ($user.'MFA Enabled' -eq 'Yes') { 'mfa-yes' } else { 'mfa-no' }
    
    $authMethodsFormatted = $user.'Auth Methods'
    if ($user.HasPhishingResistant -eq $true) {
        $authMethodsFormatted = $authMethodsFormatted -replace "windowsHelloForBusiness", "<span class='auth-method-phishing-resistant'>windowsHelloForBusiness</span>"
        $authMethodsFormatted = $authMethodsFormatted -replace "fido2SecurityKey", "<span class='auth-method-phishing-resistant'>fido2SecurityKey</span>"
        $authMethodsFormatted = $authMethodsFormatted -replace "passkeyDeviceBound", "<span class='auth-method-phishing-resistant'>passkeyDeviceBound</span>"
        $authMethodsFormatted = $authMethodsFormatted -replace "passkeyDeviceBoundAuthenticator", "<span class='auth-method-phishing-resistant'>passkeyDeviceBoundAuthenticator</span>"
        $authMethodsFormatted = $authMethodsFormatted -replace "passkeyDeviceBoundWindowsHello", "<span class='auth-method-phishing-resistant'>passkeyDeviceBoundWindowsHello</span>"
    }
    
    # Format Entra Active roles with group indicator styling
    $entraActiveFormatted = $user.'Entra Active Roles'
    if ($user.'Entra Active Roles' -like "*Global Administrator*") {
        $entraActiveFormatted = $user.'Entra Active Roles' -replace "Global Administrator", "<span style='color:#dc3545;font-weight:bold;'>Global Administrator</span>"
    }
    $entraActiveFormatted = $entraActiveFormatted -replace "\(via group\)", "<span class='via-group'>(via group)</span>"
    
    # Format Entra Eligible roles with group indicator styling
    $entraEligibleFormatted = $user.'Entra Eligible Roles'
    if ($user.'Entra Eligible Roles' -like "*Global Administrator*") {
        $entraEligibleFormatted = $user.'Entra Eligible Roles' -replace "Global Administrator", "<span style='color:#dc3545;font-weight:bold;'>Global Administrator</span>"
    }
    $entraEligibleFormatted = $entraEligibleFormatted -replace "\(via group\)", "<span class='via-group'>(via group)</span>"
    
    # Format Azure Active roles with group indicator styling
    $azActiveRoles = $user.'Azure Active Roles'
    if ($user.'Azure Active Roles' -like "*Owner*") {
        $azActiveRoles = $user.'Azure Active Roles' -replace "Owner", "<span style='color:#dc3545;font-weight:bold;'>Owner</span>"
    }
    $azActiveRoles = $azActiveRoles -replace "\(via group\)", "<span class='via-group'>(via group)</span>"
    $azActiveRolesFormatted = $azActiveRoles -replace "; ", "<br>"
    
    # Format Azure Eligible roles with group indicator styling
    $azEligibleRoles = $user.'Azure Eligible Roles'
    if ($user.'Azure Eligible Roles' -like "*Owner*") {
        $azEligibleRoles = $user.'Azure Eligible Roles' -replace "Owner", "<span style='color:#dc3545;font-weight:bold;'>Owner</span>"
    }
    $azEligibleRoles = $azEligibleRoles -replace "\(via group\)", "<span class='via-group'>(via group)</span>"
    $azEligibleRolesFormatted = $azEligibleRoles -replace "; ", "<br>"
    
    $htmlReport += "<tr>`n"
    $htmlReport += "<td>$($user.UPN)</td>`n"
    $htmlReport += "<td>$entraActiveFormatted</td>`n"
    $htmlReport += "<td>$entraEligibleFormatted</td>`n"
    $htmlReport += "<td>$azActiveRolesFormatted</td>`n"
    $htmlReport += "<td>$azEligibleRolesFormatted</td>`n"
    $htmlReport += "<td>$($user.'Total Roles')</td>`n"
    $htmlReport += "<td class='$statusClass'>$($user.'Account Status')</td>`n"
    $htmlReport += "<td class='$typeClass'>$($user.'User Type')</td>`n"
    $htmlReport += "<td class='$mfaClass'>$($user.'MFA Enabled')</td>`n"
    $htmlReport += "<td>$($user.'Last Interactive Sign In')</td>`n"
    $htmlReport += "<td>$($user.'Last Non-Interactive Sign In')</td>`n"
    $htmlReport += "<td>$authMethodsFormatted</td>`n"
    $htmlReport += "</tr>`n"
}

$htmlReport += "</tbody>`n</table>`n</div>`n"

# Add JavaScript for sorting and searching
$htmlReport += "<script>`n"
$htmlReport += "let currentSortColumn=-1;let sortAscending=true;`n"

# Sort table function
$htmlReport += @"
function sortTable(columnIndex){
    const table=document.getElementById('dataTable');
    const tbody=table.getElementsByTagName('tbody')[0];
    const rows=Array.from(tbody.getElementsByTagName('tr')).filter(row=>!row.classList.contains('hidden'));
    
    if(currentSortColumn===columnIndex){
        sortAscending=!sortAscending;
    }else{
        sortAscending=true;
        currentSortColumn=columnIndex;
    }
    
    rows.sort((a,b)=>{
        const aText=a.cells[columnIndex].textContent.trim();
        const bText=b.cells[columnIndex].textContent.trim();
        const aNum=parseFloat(aText);
        const bNum=parseFloat(bText);
        
        if(!isNaN(aNum)&&!isNaN(bNum)){
            return sortAscending?aNum-bNum:bNum-aNum;
        }else{
            return sortAscending?aText.localeCompare(bText):bText.localeCompare(aText);
        }
    });
    
    // Re-append all rows (including hidden ones) in sorted order
    const allRows=Array.from(tbody.getElementsByTagName('tr'));
    allRows.forEach(row=>{
        if(!row.classList.contains('hidden')){
            tbody.removeChild(row);
        }
    });
    rows.forEach(row=>tbody.appendChild(row));
}

// Search functionality
document.getElementById('searchBox').addEventListener('input', function(e) {
    const searchTerm = e.target.value.toLowerCase();
    const table = document.getElementById('dataTable');
    const tbody = table.getElementsByTagName('tbody')[0];
    const rows = tbody.getElementsByTagName('tr');
    let visibleCount = 0;
    
    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const text = row.textContent.toLowerCase();
        
        if (searchTerm === '' || text.includes(searchTerm)) {
            row.classList.remove('hidden');
            visibleCount++;
        } else {
            row.classList.add('hidden');
        }
    }
    
    // Update search info
    const searchInfo = document.getElementById('searchInfo');
    if (searchTerm === '') {
        searchInfo.textContent = 'Showing all ' + rows.length + ' users';
    } else {
        searchInfo.textContent = 'Showing ' + visibleCount + ' of ' + rows.length + ' users';
    }
});
"@

$htmlReport += "</script>`n"

# Add footer and close HTML
$htmlReport += "<div class='footer'><p>Need4Admin - Microsoft Privileged User Scanner v1.0 | Author: Vlad Johansen, 2025</p></div>`n"
$htmlReport += "</body>`n</html>"

# Save HTML report
$reportPath = ".\Need4Admin-Report-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').html"
$htmlReport | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "Report saved as: $reportPath" -ForegroundColor Green
Write-Host ""
Write-Host "Opening report in default browser..." -ForegroundColor Yellow

# Cross-platform browser opening
if ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6) {
    Start-Process $reportPath
} elseif ($IsMacOS) {
    & open $reportPath
} elseif ($IsLinux) {
    & xdg-open $reportPath
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "REPORT GENERATION COMPLETE" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan

# Cleanup connections
try {
    Disconnect-MgGraph | Out-Null
    Write-Host "Microsoft Graph connection closed" -ForegroundColor Yellow
} catch {
    Write-Verbose "Graph disconnect: $_"
}

try {
    if ($azureConnected) {
        Disconnect-AzAccount | Out-Null
        Write-Host "Azure connection closed" -ForegroundColor Yellow
    }
} catch {
    Write-Verbose "Azure disconnect: $_"
}

Write-Host ""
Write-Host "Script execution complete." -ForegroundColor Gray
Write-Host "You can now close this window manually." -ForegroundColor Gray