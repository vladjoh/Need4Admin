<#
=============================================================================================
Name:           Need4Admin - Microsoft Privileged User Scanner
Description:    Privileged User Scanner Script for Entra and Azure
Version:        Beta
Author:         Vlad Johansen, 2025
============================================================================================
#>

param(
    [string] $TenantId,
    [string] $ClientId,
    [string] $CertificateThumbprint
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

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Need4Admin - Microsoft Privileged User Scanner" -ForegroundColor Yellow
Write-Host "Version Beta - Author: Vlad Johansen, 2025" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Required modules with minimum versions
$requiredModules = @{
    "Microsoft.Graph.Authentication" = "2.15.0"
    "Microsoft.Graph.Users" = "2.15.0"
    "Microsoft.Graph.Identity.DirectoryManagement" = "2.15.0"
    "Microsoft.Graph.Identity.SignIns" = "2.15.0"
    "Az.Accounts" = "2.12.0"
    "Az.Resources" = "6.0.0"
}

# Check for module availability
$missingModules = @()

# Ensure CurrentUser module path is included
$env:PSModulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules;$env:PSModulePath"

foreach ($modName in $requiredModules.Keys) {
    # Force refresh of available modules
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
                Write-Host "  ✓ $modName installed successfully" -ForegroundColor Green
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
foreach ($modName in $requiredModules.Keys) {
    try {
        Import-Module $modName -Force -ErrorAction Stop
        Write-Host "  ✓ $modName loaded" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ Failed to load $modName : $_" -ForegroundColor Red
        Exit
    }
}

# Load required assembly for URL encoding
Add-Type -AssemblyName System.Web

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
if (($TenantId -ne "") -and ($ClientId -ne "") -and ($CertificateThumbprint -ne "")) {  
    Connect-MgGraph -TenantId $TenantId -AppId $ClientId -CertificateThumbprint $CertificateThumbprint -ErrorAction SilentlyContinue -ErrorVariable ConnectionError | Out-Null
    if ($ConnectionError -ne $null) {    
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
        "RoleAssignmentSchedule.ReadWrite.Directory",
        "AuditLog.Read.All"
    ) -ErrorAction SilentlyContinue -ErrorVariable ConnectionError | Out-Null
    if ($ConnectionError -ne $null) {
        Write-Host "Connection failed: $ConnectionError" -ForegroundColor Red
        Exit
    }
}

Write-Host "Microsoft Graph PowerShell module is connected successfully" -ForegroundColor Green

# Get the authenticated context for Azure connection
$context = Get-MgContext
$tenantId = $context.TenantId

# Connect to Azure using existing authentication context
Write-Host "Connecting to Azure..." -ForegroundColor Yellow
$azureConnected = $false
try {
    if (($ClientId -ne "") -and ($CertificateThumbprint -ne "")) {
        Connect-AzAccount -TenantId $tenantId -ApplicationId $ClientId -CertificateThumbprint $CertificateThumbprint -ServicePrincipal -ErrorAction Stop | Out-Null
    } else {
        Connect-AzAccount -ErrorAction Stop | Out-Null
    }
    Write-Host "Azure PowerShell module is connected successfully" -ForegroundColor Green
    $azureConnected = $true
} catch {
    Write-Host "Azure connection failed: $_" -ForegroundColor Yellow
    Write-Host "Continuing with Entra ID only..." -ForegroundColor Yellow
    $azureConnected = $false
}

Write-Host ""

function Get-MFAInfo {
    param($userId)
    $methods = @()
    $hasMFA = $false
    
    try {
        $authMethods = Get-MgUserAuthenticationMethod -UserId $userId -ErrorAction Stop
        
        foreach ($method in $authMethods) {
            $methodType = $method.AdditionalProperties.'@odata.type'
            
            switch -Wildcard ($methodType) {
                "*windowsHelloForBusinessAuthenticationMethod" { 
                    $methods += "Windows Hello for Business"
                    $hasMFA = $true
                }
                "*microsoftAuthenticatorAuthenticationMethod" { 
                    # Get detailed info for Microsoft Authenticator
                    $displayName = $method.AdditionalProperties.displayName
                    if ($displayName) {
                        if ($displayName -match "passwordless") {
                            $methods += "Microsoft Authenticator (Passwordless)"
                        } elseif ($displayName -match "passkey") {
                            $methods += "Microsoft Authenticator (Passkey)"
                        } elseif ($displayName -match "Authenticator Lite") {
                            $methods += "Authenticator Lite"
                        } else {
                            $methods += "Microsoft Authenticator (Push)"
                        }
                    } else {
                        $methods += "Microsoft Authenticator"
                    }
                    $hasMFA = $true
                }
                "*fido2AuthenticationMethod" { 
                    $methods += "FIDO2 Security Key"
                    $hasMFA = $true
                }
                "*phoneAuthenticationMethod" {
                    if ($method.AdditionalProperties.phoneType -eq "mobile") {
                        $methods += "SMS Authentication"
                    } else {
                        $methods += "Voice Call Authentication"
                    }
                    $hasMFA = $true
                }
                "*emailAuthenticationMethod" {
                    $methods += "Email Authentication"
                    $hasMFA = $true
                }
                "*temporaryAccessPassAuthenticationMethod" {
                    $methods += "Temporary Access Pass"
                    $hasMFA = $true
                }
                "*passwordAuthenticationMethod" {
                    $methods += "Password"
                    # Password alone is NOT MFA
                }
                "*softwareOathAuthenticationMethod" {
                    # This is the software token you're seeing in Entra!
                    $methods += "Software Token (OATH TOTP)"
                    $hasMFA = $true
                }
                "*certificateBasedAuthenticationMethod" {
                    $methods += "Certificate-based Authentication"
                    $hasMFA = $true
                }
                "*qrCodeAuthenticationMethod" {
                    $methods += "QR Code Authentication"
                    $hasMFA = $true
                }
                "*hardwareOathAuthenticationMethod" {
                    $methods += "Hardware Token (OATH)"
                    $hasMFA = $true
                }
                "*externalAuthenticationMethod" {
                    $methods += "External Authentication Method"
                    $hasMFA = $true
                }
                default {
                    # Catch any new authentication methods
                    $cleanType = $methodType -replace ".*#microsoft\.graph\.", "" -replace "AuthenticationMethod", ""
                    $methods += "Unknown Method ($cleanType)"
                    if ($cleanType -ne "password") {
                        $hasMFA = $true
                    }
                }
            }
        }
        
        if ($methods.Count -eq 0) { 
            $methods = @("None") 
        }
    } catch {
        $methods = @("Unable to check")
        $hasMFA = $false
    }
    
    return @{
        Methods = ($methods | Select-Object -Unique) -join "; "
        HasMFA = if ($hasMFA) { "Yes" } else { "No" }
    }
}

function Get-EligibleRoles {
    param($userId)
    
    try {
        $eligibleRoles = @()
        
        # Method 1: Use PIM API endpoint for role eligibility schedules
        try {
            $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$userId'&`$expand=roleDefinition"
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
            
            if ($response.value) {
                foreach ($item in $response.value) {
                    if ($item.status -eq "Provisioned" -and $item.roleDefinition -and $item.roleDefinition.displayName) {
                        $eligibleRoles += $item.roleDefinition.displayName
                    }
                }
            }
        } catch {
            Write-Verbose "Method 1 (roleEligibilitySchedules) failed: $_"
        }
        
        # Method 2: Fallback using PowerShell cmdlets if REST API fails
        try {
            $eligibilitySchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$userId'" -ExpandProperty "roleDefinition" -All -ErrorAction Stop
            
            foreach ($schedule in $eligibilitySchedules) {
                if ($schedule.Status -eq "Provisioned" -and $schedule.RoleDefinition -and $schedule.RoleDefinition.DisplayName) {
                    $eligibleRoles += $schedule.RoleDefinition.DisplayName
                }
            }
        } catch {
            Write-Verbose "Method 2 (Get-MgRoleManagementDirectoryRoleEligibilitySchedule) failed: $_"
        }
        
        # Method 3: Try role eligibility schedule instances as additional fallback
        try {
            $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$userId'&`$expand=roleDefinition"
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
            
            if ($response.value) {
                foreach ($item in $response.value) {
                    if ($item.roleDefinition -and $item.roleDefinition.displayName) {
                        $eligibleRoles += $item.roleDefinition.displayName
                    }
                }
            }
        } catch {
            Write-Verbose "Method 3 (roleEligibilityScheduleInstances) failed: $_"
        }
        
        # Remove duplicates and sort
        $eligibleRoles = $eligibleRoles | Where-Object { $_ -ne $null -and $_ -ne "" } | Sort-Object -Unique
        
        return $eligibleRoles
    } catch {
        Write-Warning "Error fetching eligible roles for user $userId : $_"
        return @()
    }
}

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
        
        foreach ($subscription in $subscriptions) {
            try {
                Set-AzContext -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue | Out-Null
                
                # Get active role assignments for this user in the subscription
                $roleAssignments = Get-AzRoleAssignment -ObjectId $userObjectId -ErrorAction SilentlyContinue
                
                foreach ($assignment in $roleAssignments) {
                    # Include privileged roles: Owner, anything ending with "Contributor", and specific admin roles
                    $isPrivilegedRole = $assignment.RoleDefinitionName -eq "Owner" -or 
                                       $assignment.RoleDefinitionName -like "*Contributor" -or
                                       $assignment.RoleDefinitionName -eq "Reservations Administrator" -or
                                       $assignment.RoleDefinitionName -eq "Role Based Access Control Administrator" -or
                                       $assignment.RoleDefinitionName -eq "User Access Administrator"
                    
                    if ($isPrivilegedRole) {
                        $scopeInfo = ""
                        
                        # Determine scope level and format appropriately
                        if ($assignment.Scope -eq "/subscriptions/$($subscription.Id)") {
                            # Subscription level
                            $scopeInfo = "Sub: $($subscription.Name)"
                        } elseif ($assignment.Scope -match "/subscriptions/.+/resourceGroups/([^/]+)$") {
                            # Resource Group level
                            $rgName = $matches[1]
                            $scopeInfo = "RG: $rgName (Sub: $($subscription.Name))"
                        } else {
                            # Resource level
                            $resourceName = ($assignment.Scope -split "/")[-1]
                            if ($assignment.Scope -match "/subscriptions/.+/resourceGroups/([^/]+)/") {
                                $rgName = $matches[1]
                                $scopeInfo = "Resource: $resourceName (RG: $rgName, Sub: $($subscription.Name))"
                            } else {
                                $scopeInfo = "Resource: $resourceName (Sub: $($subscription.Name))"
                            }
                        }
                        
                        $activeRoles += "$($assignment.RoleDefinitionName) -> $scopeInfo"
                    }
                }
                
                # Get PIM eligible assignments using (new method)
                try {
                    # Use the beta endpoint for role eligibility schedules as per Michev's blog
                    $uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$filter=directoryScopeId eq '/subscriptions/$($subscription.Id)' and principalId eq '$userObjectId'&`$expand=roleDefinition"
                    $headers = @{
                        'Authorization' = "Bearer $((Get-MgContext).Token)"
                        'Content-Type' = 'application/json'
                    }
                    
                    $pimResponse = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction SilentlyContinue
                    
                    if ($pimResponse.value) {
                        foreach ($eligibleAssignment in $pimResponse.value) {
                            if ($eligibleAssignment.status -eq "Provisioned" -and $eligibleAssignment.roleDefinition) {
                                $roleDefName = $eligibleAssignment.roleDefinition.displayName
                                
                                # Check if it's a privileged role using the same logic
                                $isPrivilegedRole = $roleDefName -eq "Owner" -or 
                                                   $roleDefName -like "*Contributor" -or
                                                   $roleDefName -eq "Reservations Administrator" -or
                                                   $roleDefName -eq "Role Based Access Control Administrator" -or
                                                   $roleDefName -eq "User Access Administrator"
                                
                                if ($isPrivilegedRole) {
                                    $scopeInfo = ""
                                    $scope = $eligibleAssignment.directoryScopeId
                                    
                                    # Format scope information for better readability
                                    if ($scope -eq "/subscriptions/$($subscription.Id)") {
                                        $scopeInfo = "$roleDefName → Subscription ($($subscription.Name))"
                                    } elseif ($scope -match "/subscriptions/.+/resourceGroups/([^/]+)$") {
                                        $rgName = $matches[1]
                                        $scopeInfo = "$roleDefName → Resource Group ($rgName)"
                                    } elseif ($scope -match "/subscriptions/.+/resourceGroups/([^/]+)/.+") {
                                        # Individual Resource level
                                        $resourceName = ($scope -split "/")[-1]
                                        $scopeInfo = "$roleDefName → Resource ($resourceName)"
                                    } else {
                                        # Other scope
                                        $resourceName = ($scope -split "/")[-1]
                                        $scopeInfo = "$roleDefName → Other ($resourceName)"
                                    }
                                    
                                    $eligibleRoles += $scopeInfo
                                }
                            }
                        }
                    }
                } catch {
                    Write-Verbose "NEW method failed for subscription $($subscription.Name): $_"
                    
                    # Fallback to original REST API method with management endpoint
                    try {
                        $context = Get-AzContext
                        $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                            $context.Account, 
                            $context.Environment, 
                            $context.Tenant.Id, 
                            $null, 
                            "Never", 
                            $null, 
                            "https://management.azure.com/"
                        ).AccessToken
                        
                        $headers = @{
                            'Authorization' = "Bearer $token"
                            'Content-Type' = 'application/json'
                        }
                        
                        # Updated API endpoint for PIM role eligibility schedules
                        $pimUri = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01-preview&`$filter=principalId eq '$userObjectId'"
                        $pimResponse = Invoke-RestMethod -Uri $pimUri -Headers $headers -Method GET -ErrorAction SilentlyContinue
                        
                        if ($pimResponse.value) {
                            foreach ($eligibleRequest in $pimResponse.value) {
                                if ($eligibleRequest.properties.status -eq "Provisioned") {
                                    # Get role definition details
                                    $roleDefId = $eligibleRequest.properties.roleDefinitionId
                                    $roleDefUri = "https://management.azure.com$($roleDefId)?api-version=2022-04-01"
                                    $roleDefResponse = Invoke-RestMethod -Uri $roleDefUri -Headers $headers -Method GET -ErrorAction SilentlyContinue
                                    
                                    if ($roleDefResponse) {
                                        # Check if it's a privileged role using the same logic
                                        $isPrivilegedRole = $roleDefResponse.properties.roleName -eq "Owner" -or 
                                                           $roleDefResponse.properties.roleName -like "*Contributor" -or
                                                           $roleDefResponse.properties.roleName -eq "Reservations Administrator" -or
                                                           $roleDefResponse.properties.roleName -eq "Role Based Access Control Administrator" -or
                                                           $roleDefResponse.properties.roleName -eq "User Access Administrator"
                                        
                                        if ($isPrivilegedRole) {
                                            $scopeInfo = ""
                                            $scope = $eligibleRequest.properties.scope
                                            
                                            # Format scope information for better readability
                                            if ($scope -eq "/subscriptions/$($subscription.Id)") {
                                                $scopeInfo = "$($roleDefResponse.properties.roleName) → Subscription ($($subscription.Name))"
                                            } elseif ($scope -match "/subscriptions/.+/resourceGroups/([^/]+)$") {
                                                $rgName = $matches[1]
                                                $scopeInfo = "$($roleDefResponse.properties.roleName) → Resource Group ($rgName)"
                                            } elseif ($scope -match "/subscriptions/.+/resourceGroups/([^/]+)/.+") {
                                                # Individual Resource level
                                                $resourceName = ($scope -split "/")[-1]
                                                $scopeInfo = "$($roleDefResponse.properties.roleName) → Resource ($resourceName)"
                                            } else {
                                                # Other scope
                                                $resourceName = ($scope -split "/")[-1]
                                                $scopeInfo = "$($roleDefResponse.properties.roleName) → Other ($resourceName)"
                                            }
                                            
                                            $eligibleRoles += $scopeInfo
                                        }
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Verbose "Fallback method also failed for subscription $($subscription.Name): $_"
                    }
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

foreach ($role in $relevantRoles) {
    $currentRole++
    Write-Progress -Activity "Scanning users for admin roles" -Status "Processing $($role.DisplayName) ($currentRole/$totalRoles)" -PercentComplete (($currentRole / $totalRoles) * 100)
    
    # Get all members of this role
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
    
    foreach ($member in $members) {
        if ($member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
            $userId = $member.Id
            if (-not $userRolesMap.ContainsKey($userId)) {
                $userRolesMap[$userId] = [System.Collections.ArrayList]::new()
            }
            $null = $userRolesMap[$userId].Add($role.DisplayName)
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

Write-Host "Found $totalUsers privileged users. Fetching details..." -ForegroundColor Green

# Get real-time sign-in data for all users in one efficient call
Write-Host "Getting recent sign-in activity..." -ForegroundColor Yellow
$global:SignInCache = @{}

try {
    # Get recent sign-ins for ALL users in one bulk call
    $lookBackDays = 30  # 
    $lookBackTime = [DateTime]::UtcNow.AddDays(-$lookBackDays).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $lookBackTime&`$top=1000&`$orderby=createdDateTime desc"
    $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop
    
    if ($response.value) {
        # Process sign-ins and build cache for our users
        foreach ($signIn in $response.value) {
            $userId = $signIn.userId
            
            # Only cache data for our privileged users
            if ($userIds -contains $userId) {
                if (-not $global:SignInCache.ContainsKey($userId)) {
                    $global:SignInCache[$userId] = @{
                        Interactive = $null
                        NonInteractive = $null
                    }
                }
                
                # Store most recent of each type
                if ($signIn.isInteractive -eq $true -and -not $global:SignInCache[$userId].Interactive) {
                    $global:SignInCache[$userId].Interactive = $signIn.createdDateTime
                }
                elseif ($signIn.isInteractive -eq $false -and -not $global:SignInCache[$userId].NonInteractive) {
                    $global:SignInCache[$userId].NonInteractive = $signIn.createdDateTime
                }
            }
        }
    }
} catch {
    Write-Verbose "Real-time sign-in fetch failed, using cached SignInActivity as fallback"
}

$processedCount = 0
foreach ($userId in $userIds) {
    $processedCount++
    Write-Progress -Activity "Processing users" -Status "User $processedCount of $totalUsers (including Azure roles...)" -PercentComplete (($processedCount / $totalUsers) * 100)
    
    try {
        # Get user with extended properties for hybrid detection
        $user = Get-MgUser -UserId $userId -Property "Id,UserPrincipalName,DisplayName,AccountEnabled,Mail,OnPremisesSyncEnabled,OnPremisesSecurityIdentifier,OnPremisesSamAccountName,OnPremisesUserPrincipalName,OnPremisesImmutableId" -ErrorAction Stop
        
        # Get sign-in data from cache (real-time data) or fallback to SignInActivity
        $interactiveSignIn = "Never"
        $nonInteractiveSignIn = "Never"
        
        # Check cache first (real-time data from sign-in logs)
        if ($global:SignInCache.ContainsKey($userId)) {
            if ($global:SignInCache[$userId].Interactive) {
                try {
                    $signInTime = [DateTime]::Parse($global:SignInCache[$userId].Interactive)
                    $interactiveSignIn = $signInTime.ToString("yyyy-MM-dd HH:mm")
                } catch {
                    $interactiveSignIn = "Parse error"
                }
            }
            
            if ($global:SignInCache[$userId].NonInteractive) {
                try {
                    $signInTime = [DateTime]::Parse($global:SignInCache[$userId].NonInteractive)
                    $nonInteractiveSignIn = $signInTime.ToString("yyyy-MM-dd HH:mm")
                } catch {
                    $nonInteractiveSignIn = "Parse error"
                }
            }
        }
        
        # Fallback to SignInActivity if not in cache or cache values are null
        if ($interactiveSignIn -eq "Never" -or $nonInteractiveSignIn -eq "Never") {
            try {
                $userWithSignIn = Get-MgUser -UserId $userId -Property "SignInActivity" -ErrorAction SilentlyContinue
                if ($userWithSignIn.SignInActivity) {
                    if ($interactiveSignIn -eq "Never" -and $userWithSignIn.SignInActivity.LastSignInDateTime) {
                        $interactiveSignIn = ([DateTime]$userWithSignIn.SignInActivity.LastSignInDateTime).ToString("yyyy-MM-dd HH:mm")
                    }
                    if ($nonInteractiveSignIn -eq "Never" -and $userWithSignIn.SignInActivity.LastNonInteractiveSignInDateTime) {
                        $nonInteractiveSignIn = ([DateTime]$userWithSignIn.SignInActivity.LastNonInteractiveSignInDateTime).ToString("yyyy-MM-dd HH:mm")
                    }
                }
            } catch {
                Write-Verbose "SignInActivity fallback failed for user $userId"
            }
        }
        
        $userRoles = $userRolesMap[$userId]
        $eligibleRoles = Get-EligibleRoles -userId $userId
        $userType = Get-UserType -user $user
        
        # Get Azure role assignments
        $azureRoles = Get-AzureRoleAssignments -userObjectId $userId
        
        # Get MFA info
        $authMethods = Get-MFAInfo -userId $userId
        
        # Format roles for display with new column names
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
        
        # Format Azure roles for display with multi-line structure
        $azActiveRolesDisplay = if ($azureRoles.ActiveRoles.Count -gt 0) {
            # Sort roles with Owner first, then alphabetically
            $sortedRoles = $azureRoles.ActiveRoles | Sort-Object { if ($_ -like "*Owner*") { "0" } else { "1" + $_ } }
            ($sortedRoles -join "<br>")
        } else {
            "None"
        }
        
        $azEligibleRolesDisplay = if ($azureRoles.EligibleRoles.Count -gt 0) {
            # Sort roles with Owner first, then alphabetically
            $sortedRoles = $azureRoles.EligibleRoles | Sort-Object { if ($_ -like "*Owner*") { "0" } else { "1" + $_ } }
            ($sortedRoles -join "<br>")
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
            'Is Global Admin' = if (($userRoles | Sort-Object) -contains "Global Administrator") { $true } else { $false }
        }
    } catch {
        Write-Warning "Failed to process user $userId : $_"
    }
}

Write-Progress -Activity "Processing users" -Completed

# Get context info for report
$context = Get-MgContext
$tenantId = $context.TenantId
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
    
    # Count Azure roles (handle both separators)
    if ($user.'Azure Active Roles' -ne 'None') {
        $azureActiveRolesCount += ($user.'Azure Active Roles' -split '<br>|; ').Count
    }
    if ($user.'Azure Eligible Roles' -ne 'None') {
        $azureEligibleRolesCount += ($user.'Azure Eligible Roles' -split '<br>|; ').Count
    }
}

$usersWithoutMFA = ($privilegedUsers | Where-Object { $_.'MFA Enabled' -eq 'No' }).Count

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "SCAN COMPLETED" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Total Privileged Users: $totalUsers" -ForegroundColor Yellow
Write-Host "Active Users: $activeUsers" -ForegroundColor Yellow
Write-Host "Hybrid Users: $hybridUsers" -ForegroundColor Yellow
Write-Host "Entra Active Roles Count: $entraActiveRolesCount" -ForegroundColor Yellow
Write-Host "Entra Eligible Roles Count: $entraEligibleRolesCount" -ForegroundColor Yellow
Write-Host "Azure Active Roles Count: $azureActiveRolesCount" -ForegroundColor Magenta
Write-Host "Azure Eligible Roles Count: $azureEligibleRolesCount" -ForegroundColor Magenta
Write-Host "Users without MFA: $usersWithoutMFA" -ForegroundColor Yellow
Write-Host "Tenant ID: $tenantId" -ForegroundColor Yellow
Write-Host "Signed in as: $signedInUser" -ForegroundColor Yellow
Write-Host ""

# Generate HTML report
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Need4Admin - Privileged Users Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .azure-badge { background-color: #ff6600; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin-left: 10px; }
        .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; }
        .summary-item { text-align: center; padding: 10px; background-color: #f8f9fa; border-radius: 3px; }
        .summary-number { font-size: 24px; font-weight: bold; color: #0078d4; }
        .summary-label { font-size: 12px; color: #666; margin-top: 5px; }
        .azure-summary { color: #ff6600; }
        table { width: 100%; border-collapse: collapse; background-color: white; border-radius: 5px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); font-size: 13px; }
        th { background-color: #f8f9fa; padding: 10px 8px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; }
        td { padding: 8px; border-bottom: 1px solid #dee2e6; vertical-align: top; }
        tr:hover { background-color: #f8f9fa; }
        .status-active { color: #28a745; font-weight: bold; }
        .status-disabled { color: #dc3545; font-weight: bold; }
        .type-hybrid { color: #fd7e14; font-weight: bold; }
        .type-cloud { color: #0078d4; font-weight: bold; }
        .mfa-yes { color: #28a745; font-weight: bold; }
        .mfa-no { color: #dc3545; font-weight: bold; }
        .footer { margin-top: 20px; text-align: center; color: #666; font-size: 12px; }
        .scroll-container { overflow-x: auto; }
        /* Sortable table styles */
        .sortable th { cursor: pointer; position: relative; user-select: none; resize: horizontal; overflow: hidden; }
        .sortable th:hover { background-color: #e9ecef; }
        .sortable th::after { content: ' ↕'; color: #aaa; font-size: 10px; }
        /* Resizable columns */
        .sortable th { border-right: 2px solid #dee2e6; min-width: 100px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Need4Admin - Privileged Users Report</h1>
        <p>Generated on: $timestamp | Tenant: $tenantId | Signed in as: $signedInUser</p>
    </div>
    
    <div class="summary">
        <div class="summary-grid">
            <div class="summary-item">
                <div class="summary-number">$totalUsers</div>
                <div class="summary-label">Total Users</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">$activeUsers</div>
                <div class="summary-label">Active Users</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">$hybridUsers</div>
                <div class="summary-label">Hybrid Users</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">$entraActiveRolesCount</div>
                <div class="summary-label">Entra Active Roles</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">$entraEligibleRolesCount</div>
                <div class="summary-label">Entra Eligible Roles</div>
            </div>
            <div class="summary-item">
                <div class="summary-number azure-summary">$azureActiveRolesCount</div>
                <div class="summary-label">Azure Active Roles</div>
            </div>
            <div class="summary-item">
                <div class="summary-number azure-summary">$azureEligibleRolesCount</div>
                <div class="summary-label">Azure Eligible Roles</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">$usersWithoutMFA</div>
                <div class="summary-label">Without MFA</div>
            </div>
        </div>
    </div>
    
    <div class="scroll-container">
    <table class="sortable">
        <thead>
            <tr>
                <th>UPN</th>
                <th style="background-color: #e3f2fd;">Entra Active Roles</th>
                <th style="background-color: #e3f2fd;">Entra Eligible Roles</th>
                <th>Azure Active Roles</th>
                <th>Azure Eligible Roles</th>
                <th>Total</th>
                <th>Status</th>
                <th>Type</th>
                <th>MFA</th>
                <th>Last Interactive Sign In</th>
                <th>Last Non-Interactive Sign In</th>
                <th>Auth Methods</th>
            </tr>
        </thead>
        <tbody>
"@

foreach ($user in $privilegedUsers) {
    $statusClass = if ($user.'Account Status' -eq 'Active') { 'status-active' } else { 'status-disabled' }
    $typeClass = if ($user.'User Type' -eq 'Hybrid') { 'type-hybrid' } else { 'type-cloud' }
    $mfaClass = if ($user.'MFA Enabled' -eq 'Yes') { 'mfa-yes' } else { 'mfa-no' }
    
    # Highlight only specific roles and MFA No in red text
    $upnClass = ""
    $mfaClass = if ($user.'MFA Enabled' -eq 'Yes') { 'mfa-yes' } else { 'mfa-no' }
    
    # Check for Global Administrator in both Active and Eligible Entra roles
    if ($user.'Entra Active Roles' -like "*Global Administrator*") {
        $entraActiveFormatted = $user.'Entra Active Roles' -replace "Global Administrator", "<span style='color: #dc3545; font-weight: bold;'>Global Administrator</span>"
    } else {
        $entraActiveFormatted = $user.'Entra Active Roles'
    }
    
    if ($user.'Entra Eligible Roles' -like "*Global Administrator*") {
        $entraEligibleFormatted = $user.'Entra Eligible Roles' -replace "Global Administrator", "<span style='color: #dc3545; font-weight: bold;'>Global Administrator</span>"
    } else {
        $entraEligibleFormatted = $user.'Entra Eligible Roles'
    }
    
    # Check for Owner role in both Active and Eligible Azure roles, and sort Owner first
    if ($user.'Azure Active Roles' -like "*Owner*") {
        # Split roles, put Owner first, then highlight Owner text
        $azureActiveList = ($user.'Azure Active Roles' -split "<br>") | Sort-Object { if ($_ -like "*Owner*") { "0" } else { "1" + $_ } }
        $azureActiveText = ($azureActiveList -join "<br>") -replace "Owner", "<span style='color: #dc3545; font-weight: bold;'>Owner</span>"
        $azActiveRoles = $azureActiveText
    } else {
        $azActiveRoles = $user.'Azure Active Roles'
    }
    
    if ($user.'Azure Eligible Roles' -like "*Owner*") {
        # Split roles, put Owner first, then highlight Owner text
        $azureEligibleList = ($user.'Azure Eligible Roles' -split "<br>") | Sort-Object { if ($_ -like "*Owner*") { "0" } else { "1" + $_ } }
        $azureEligibleText = ($azureEligibleList -join "<br>") -replace "Owner", "<span style='color: #dc3545; font-weight: bold;'>Owner</span>"
        $azEligibleRoles = $azureEligibleText
    } else {
        $azEligibleRoles = $user.'Azure Eligible Roles'
    }
    
    $htmlReport += @"
            <tr>
                <td style="$upnClass">$($user.UPN)</td>
                <td style="background-color: #f3f8ff;">$entraActiveFormatted</td>
                <td style="background-color: #f3f8ff;">$entraEligibleFormatted</td>
                <td>$azActiveRoles</td>
                <td>$azEligibleRoles</td>
                <td>$($user.'Total Roles')</td>
                <td class="$statusClass">$($user.'Account Status')</td>
                <td class="$typeClass">$($user.'User Type')</td>
                <td class="$mfaClass">$($user.'MFA Enabled')</td>
                <td>$($user.'Last Interactive Sign In')</td>
                <td>$($user.'Last Non-Interactive Sign In')</td>
                <td>$($user.'Auth Methods')</td>
            </tr>
"@
}

$htmlReport += @"
        </tbody>
    </table>
    </div>
    
    <script>
    // Simple table sorting functionality
    document.addEventListener('DOMContentLoaded', function() {
        const table = document.querySelector('.sortable');
        const headers = table.querySelectorAll('th');
        
        headers.forEach((header, index) => {
            header.addEventListener('click', () => {
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                const isAscending = header.classList.contains('asc');
                
                // Remove sort classes from all headers
                headers.forEach(h => h.classList.remove('asc', 'desc'));
                
                // Add appropriate class to clicked header
                header.classList.add(isAscending ? 'desc' : 'asc');
                
                rows.sort((a, b) => {
                    const aText = a.cells[index].textContent.trim();
                    const bText = b.cells[index].textContent.trim();
                    
                    // Try to sort as numbers first, then as text
                    const aNum = parseFloat(aText);
                    const bNum = parseFloat(bText);
                    
                    if (!isNaN(aNum) && !isNaN(bNum)) {
                        return isAscending ? bNum - aNum : aNum - bNum;
                    } else {
                        return isAscending ? bText.localeCompare(aText) : aText.localeCompare(bText);
                    }
                });
                
                // Reorder the rows
                rows.forEach(row => tbody.appendChild(row));
            });
        });
    });
    </script>
    
    <div class="footer">
        <p>Need4Admin - Microsoft Privileged User Scanner | Author: Vlad Johansen, 2025</p>
    </div>
</body>
</html>
"@

# Save HTML report
$reportPath = ".\Need4Admin-Enhanced-Report-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').html"
$htmlReport | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "Enhanced report saved as: $reportPath" -ForegroundColor Green
Write-Host ""
Write-Host "Opening report in default browser..." -ForegroundColor Yellow
Start-Process $reportPath

# Also export as CSV
$csvPath = ".\Need4Admin-Enhanced-Report-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').csv"
$privilegedUsers | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "Enhanced CSV export saved as: $csvPath" -ForegroundColor Green

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
Write-Host "Reports are ready for analysis. Script execution complete." -ForegroundColor Gray
Write-Host "You can now close this window manually." -ForegroundColor Gray