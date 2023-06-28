Clear-Host
#************************************************** IMPORTANT ************************************         
# Defines a list of users to exclude in the different script processes (using userPrincipalName) *
  $ListeExclus = @(
                   "empty1@empty.com"
                   "empty2@empty.com"                            
                   "empty3@empty.com"                                     
                    )
#************************************************** IMPORTANT ************************************   *    
# Check if $ListeExclus has been edited.
if ("empty1@empty.com" -in $ListeExclus) {
    Write-Host "Before it can be launched," -ForegroundColor Red
    Write-Host "MfaPasslessPizazz needs an edited `$ListeExclus!" -ForegroundColor Red
    Start-Sleep -Seconds 6
    exit
}


$title0 = @"
`n
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
██░▄▀▄░█░▄▄█░▄▄▀██░▄▄░█░▄▄▀█░▄▄█░▄▄█░██░▄▄█░▄▄█░▄▄██░▄▄░██▄██▄▄░█░▄▄▀█▄▄░█▄▄░██
██░█░█░█░▄██░▀▀░██░▀▀░█░▀▀░█▄▄▀█▄▄▀█░██░▄▄█▄▄▀█▄▄▀██░▀▀░██░▄█▀▄██░▀▀░█▀▄██▀▄███
██░███░█▄███▄██▄██░████▄██▄█▄▄▄█▄▄▄█▄▄█▄▄▄█▄▄▄█▄▄▄██░████▄▄▄█▄▄▄█▄██▄█▄▄▄█▄▄▄██
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                   Adding a dash of pizazz to your MFA and passwordless journey 
`n
"@

$title1 = @"
░▒█░▒█░▄▀▀▄░█▀▄░█▀▀▄░▀█▀░█▀▀░░░▀▀█▀▀░▄▀▀▄░▄▀▀▄░█░
░▒█░▒█░█▄▄█░█░█░█▄▄█░░█░░█▀▀░░░░▒█░░░█░░█░█░░█░█░
░░▀▄▄▀░█░░░░▀▀░░▀░░▀░░▀░░▀▀▀░░░░▒█░░░░▀▀░░░▀▀░░▀▀
             Jazz up user MFA/Passwordless updates
`n
"@

$title2 = @"                          
░▒█▀▀▄░█▀▀░█▀▀░█▀▀░▀█▀░░░▀▀█▀▀░▄▀▀▄░▄▀▀▄░█░
░▒█▄▄▀░█▀▀░▀▀▄░█▀▀░░█░░░░░▒█░░░█░░█░█░░█░█░
░▒█░▒█░▀▀▀░▀▀▀░▀▀▀░░▀░░░░░▒█░░░░▀▀░░░▀▀░░▀▀
     Tokens away, the MfaPasslessPizazz way!
`n
"@

$title3 = @"
░▒█▀▀█░█░░░█░█▀▄░█░░█▀▀░█▀▀░█▀▀░░░▀▀█▀▀░▄▀▀▄░▄▀▀▄░█░
░▒█▄▄█░▀▄█▄▀░█░█░█░░█▀▀░▀▀▄░▀▀▄░░░░▒█░░░█░░█░█░░█░█░
░▒█░░░░░▀░▀░░▀▀░░▀▀░▀▀▀░▀▀▀░▀▀▀░░░░▒█░░░░▀▀░░░▀▀░░▀▀
Full passwordless? Make it the MfaPasslessPizazz way!
`n
"@

$title4 = @"
░▀▀█▀▀░█▀▀░█▀▄▀█░▄▀▀▄░░░█▀▀▄░█▀▄░█▀▄░█▀▀░█▀▀░█▀▀░░░▒█▀▀█░█▀▀▄░█▀▀░█▀▀
░░▒█░░░█▀▀░█░▀░█░█▄▄█░░▒█▄▄█░█░░░█░░░█▀▀░▀▀▄░▀▀▄░░░▒█▄▄█░█▄▄█░▀▀▄░▀▀▄
░░▒█░░░▀▀▀░▀░░▒▀░█░░░░░▒█░▒█░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀▀▀░░░▒█░░░░▀░░▀░▀▀▀░▀▀▀
                            Dive into Temporary Access Pass management
`n
"@

$title5 = @"
`n
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
██░▄▀▄░█░▄▄█░▄▄▀██░▄▄░█░▄▄▀█░▄▄█░▄▄█░██░▄▄█░▄▄█░▄▄██░▄▄░██▄██▄▄░█░▄▄▀█▄▄░█▄▄░██
██░█░█░█░▄██░▀▀░██░▀▀░█░▀▀░█▄▄▀█▄▄▀█░██░▄▄█▄▄▀█▄▄▀██░▀▀░██░▄█▀▄██░▀▀░█▀▄██▀▄███
██░███░█▄███▄██▄██░████▄██▄█▄▄▄█▄▄▄█▄▄█▄▄▄█▄▄▄█▄▄▄██░████▄▄▄█▄▄▄█▄██▄█▄▄▄█▄▄▄██
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
░█▀▀▄░█░▒█░▀█▀░▄▀▀▄░▒█▀▀▄░▄▀▀▄░█▀▀▄░█▀▀
▒█▄▄█░█░▒█░░█░░█░░█░▒█░░░░█░░█░█░▒█░█▀░
▒█░▒█░░▀▀▀░░▀░░░▀▀░░▒█▄▄▀░░▀▀░░▀░░▀░▀░░
                     Unlock the enchantment of MfaPasslessPizazz with AutoConf!
`n
"@  

do {
Clear-Host
Write-Host $title0

    Write-Host "Take the Fun Ride with MfaPasslessPizazz:"
    Write-Host "1. Execute the Update Tool"
    Write-Host "2. Execute the Reset Tool"
    Write-Host "3. Execute the Passwordless Tool"
    Write-Host "4. Dive into TAP Management"
    Write-Host "5. Exit"

    Write-Host "`n`n99. *** Execute the AutoConf Script ***`n"

    Write-Host "Important: After using options 2, 3, or 4," -ForegroundColor Green
    Write-Host "you MUST use the Update Tool to apply changes." -ForegroundColor Green
    Write-Host "Due to API Graph's latency, run the 1. Update Tool a few minutes after setting new parameters!`n" -ForegroundColor Green


    Write-Host "Ready to roll?"
    $Choice = Read-Host -Prompt "Make your move"


    switch ($Choice) {

                      "1" { # *** BEGIN Update Tool ***
                                
                            Clear-Host      
                            # Display the title
                            Write-Host $title1

                            # Initialize the variable to store the logs
                            $sessionLogs = @()

                            # Log file path in the same location as the script
                            $logFile = Join-Path -Path $PSScriptRoot -ChildPath "Log_UpdateTool.log"
                            # Check if the file exists, otherwise create it
                            if (-not (Test-Path $logFile)) {
                                $null = New-Item -Path $logFile -ItemType File
                            }

                            # Completely uninstall Microsoft.Graph module in case of issues
                            # Get-Module -ListAvailable -Name 'Microsoft.Graph*' | Uninstall-Module

                            Write-Host "Checking the installation of the Microsoft.Graph module...`n"
                            # Check if the Microsoft.Graph module is installed
                            if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
                                # If the module is not installed, install it
                                Write-Host "Installing the Microsoft.Graph module..."
                                Install-Module -Name Microsoft.Graph -Force
                            }

                            # By default, Microsoft Graph PowerShell commands target the v1.0 API version.
                            # Commands for APIs that are only available in beta version are not available in PowerShell by default.
                            # We need to load the Beta profile to access all the commands...
                            Select-MgProfile -Name Beta

                            Write-Host "Loading the Microsoft.Graph.Groups module..."
                            # Check if the Microsoft.Graph.Groups module is already loaded
                            if (-not (Get-Module -Name Microsoft.Graph.Groups)) {
                                # If the module is not already loaded, load the Microsoft.Graph.Groups module in PowerShell
                                Import-Module -Name Microsoft.Graph.Groups
                            }

                            Write-Host "Loading the Microsoft.Graph.Users module...`n"
                            # Check if the Microsoft.Graph.Users module is already loaded
                            if (-not (Get-Module -Name Microsoft.Graph.Users)) {
                                # If the module is not already loaded, load the Microsoft.Graph.Users module in PowerShell
                                Import-Module -Name Microsoft.Graph.Users
                            }

                            Write-Host "Connecting to the Graph API..."
                            # Establish a connection between the PowerShell session and the Microsoft Graph API with the necessary permissions.
                            Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All", "AuditLog.Read.All"
                            # AuditLog.Read.All --> Allows reading all audit logs.
                            # User.ReadWrite.All --> Allows reading and writing user profiles.
                            # Group.ReadWrite.All --> Allows reading and writing groups.

                            Write-Host "`nRetrieving user details..."
                            # Retrieve all users with their registration details.
                            $Uri = 'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails'
                            $AllUsers = @()
                            do {
                                $result = Invoke-GraphRequest -Uri $Uri
                                $AllUsers += $result.Value
                                $Uri = $result.'@odata.nextLink' # By default, Microsoft Graph API returns a maximum of 200 objects per page. OData allows querying as long as there are more pages.
                            } while ($Uri)

                            # Store the details of all users in a variable
                            $DetailsUsers = foreach ($user in $AllUsers) {
                                $details = @{
                                    "User Name"         = $user.userPrincipalName  # --> User principal name.
                                    "Object ID"         = $user.id # --> User object ID.
                                    "isMfaRegistered"   = $user.isMfaRegistered # --> Indicates if the user is registered for multi-factor authentication (MFA).
                                    "isMfaCapable"      = $user.isMfaCapable # --> Indicates if the user is capable of supporting MFA.
                                    "methodsRegistered" = $user.methodsRegistered # --> Indicates the registered authentication methods for the user (Microsoft Authenticator, mobile phone, security keys, etc.).
                                    "defaultMfaMethod"  = $user.defaultMfaMethod # --> Indicates the user's default MFA method.
                                }
                                New-Object -TypeName PSObject -Property $details
                            }

                            Write-Host "Filtering and sorting users..."
                            # Retrieve the IDs of the members to exclude from processing
                            $ExcludedUsers = $ListeExclus | ForEach-Object { (Get-MgUser -Filter "userPrincipalName eq '$_'").Id }

                            # Filter users who have not configured/activated MFA, taking into account the excluded users.
                            $UsersSansMfa = foreach ($user in $DetailsUsers) {
                                # Check if the user meets the filtering criteria
                                if (($user.isMfaRegistered -eq $false) -and ($user.'Object ID' -notin $ExcludedUsers)) {
                                    $user
                                }
                            }

                            # Filter users with MFA, excluding users without MFA and excluded users.
                            $UsersAvecMfa = $DetailsUsers | Where-Object {
                                $_.'Object ID' -notin $UsersSansMfa.'Object ID' -and $_.'Object ID' -notin $ExcludedUsers
                            }

                            # Filter users with MFA using Microsoft Authenticator Push and/or FIDO2 Security Key.
                            $AuthenticatorFido2 = $UsersAvecMfa | Where-Object {
                                ($_.methodsRegistered -contains 'microsoftAuthenticatorPush' -and $_.methodsRegistered -contains 'fido2SecurityKey') -or
                                ($_.methodsRegistered -contains 'microsoftAuthenticatorPush')
                            }

                            # Filter users with MFA using FIDO2 Security Key but not Microsoft Authenticator Push.
                            $Fido2 = $UsersAvecMfa | Where-Object {
                                $_.methodsRegistered -contains 'fido2SecurityKey' -and $_.methodsRegistered -notcontains 'microsoftAuthenticatorPush'
                            }

                            Write-Host "Processing groups..."
                            # Check if the groups already exist
                            $Group1 = Get-MgGroup -Filter "displayName eq 'MFA_NotConfigured'"
                            $Group2 = Get-MgGroup -Filter "displayName eq 'MFA_Authenticator+FIDO2'"
                            $Group3 = Get-MgGroup -Filter "displayName eq 'MFA_FIDO2_Passwordless'"

                            # Create the MFA_NotConfigured group if it doesn't already exist
                            if (-not $Group1) {
                                $newGroupParams = @{
                                    DisplayName     = "MFA_NotConfigured"
                                    Description     = "Group for users without MFA configuration"
                                    MailEnabled     = $false
                                    SecurityEnabled = $true
                                    MailNickname    = "MFA_NotConfigured"
                                }
                                $Group1 = New-MgGroup @newGroupParams
                            }

                            # Create the MFA_Authenticator+FIDO2 group if it doesn't already exist
                            if (-not $Group2) {
                                $newGroupParams = @{
                                    DisplayName     = "MFA_Authenticator+FIDO2"
                                    Description     = "Group for users with MFA Authenticator(push+password) or FIDO2 Passwordless"
                                    MailEnabled     = $false
                                    SecurityEnabled = $true
                                    MailNickname    = "MFA_Authenticator+FIDO2"
                                }
                                $Group2 = New-MgGroup @newGroupParams
                            }

                            # Create the MFA_FIDO2_Passwordless group if it doesn't already exist
                            if (-not $Group3) {
                                $newGroupParams = @{
                                    DisplayName     = "MFA_FIDO2_Passwordless"
                                    Description     = "Group for users with MFA FIDO2 Passwordless"
                                    MailEnabled     = $false
                                    SecurityEnabled = $true
                                    MailNickname    = "MFA_FIDO2_Passwordless"
                                }
                                $Group3 = New-MgGroup @newGroupParams
                            }

                            Write-Host "Assigning users (MFA_NotConfigured or MFA_Authenticator+FIDO2 or MFA_FIDO2_Passwordless)...`n`n"
                            # Get the current members of the MFA_NotConfigured and MFA_Authenticator+FIDO2 groups
                            $currentMembersGroup1 = Get-MgGroupMember -GroupId $Group1.Id -All | Select-Object -ExpandProperty Id # Microsoft Graph has a limit of 100 objects per request (pagination) -All bypasses pagination. 
                            $currentMembersGroup2 = Get-MgGroupMember -GroupId $Group2.Id -All | Select-Object -ExpandProperty Id 
                            $currentMembersGroup3 = Get-MgGroupMember -GroupId $Group3.Id -All | Select-Object -ExpandProperty Id

                            # Add UsersSansMfa users to the MFA_NotConfigured group
                            $usersToAddGroup1 = $UsersSansMfa | Where-Object { $_."Object ID" -notin $currentMembersGroup1 }
                            $usersToAddGroup1 | ForEach-Object {
                                $userId = $_."Object ID"
                                $userName = $_."User Name"

                                # If the user does not have a TAP, then add them to the group
                                    if ((Get-MgGroupMember -GroupId $Group1.Id -Filter "id eq '$userId'"-ErrorAction SilentlyContinue).Count -eq 0) {
                                        New-MgGroupMember -GroupId $Group1.Id -DirectoryObjectId $userId
                                        # Add entry to the log
                                        $logEntry = "{0} - [ADD] {1} to the MFA_NotConfigured group" -f (Get-Date), $userName
                                        Add-Content -Path $logFile -Value $logEntry
                                        $sessionLogs += $logEntry
                                    }                   
                            }

                            # Add AuthenticatorFido2 users to the MFA_Authenticator+FIDO2 group
                            $usersToAddGroup2 = $AuthenticatorFido2 | Where-Object { $_."Object ID" -notin $currentMembersGroup2 }
                            $usersToAddGroup2 | ForEach-Object {
                                $userId = $_."Object ID"
                                $userName = $_."User Name"

                                if ((Get-MgGroupMember -GroupId $Group2.Id -Filter "id eq '$userId'"-ErrorAction SilentlyContinue).Count -eq 0) {
                                    New-MgGroupMember -GroupId $Group2.Id -DirectoryObjectId $userId
                                    $logEntry = "{0} - [ADD] {1} to the MFA_Authenticator+FIDO2 group" -f (Get-Date), $userName
                                    Add-Content -Path $logFile -Value $logEntry
                                    $sessionLogs += $logEntry
                                }
                            }

                            # Add Fido2 users to the MFA_FIDO2_Passwordless group
                            $usersToAddGroup3 = $Fido2 | Where-Object { $_."Object ID" -notin $currentMembersGroup3 }
                            $usersToAddGroup3 | ForEach-Object {
                                $userId = $_."Object ID"
                                $userName = $_."User Name"

                                if ((Get-MgGroupMember -GroupId $Group3.Id -Filter "id eq '$userId'"-ErrorAction SilentlyContinue).Count -eq 0) {
                                    New-MgGroupMember -GroupId $Group3.Id -DirectoryObjectId $userId
                                    $logEntry = "{0} - [ADD] {1} to the MFA_FIDO2_Passwordless group" -f (Get-Date), $userName
                                    Add-Content -Path $logFile -Value $logEntry
                                    $sessionLogs += $logEntry
                                }
                            }

                            # Remove users who are present in the MFA_NotConfigured group but not in UsersSansMfa
                            $usersToRemoveGroup1 = $currentMembersGroup1 | Where-Object { $_ -notin $UsersSansMfa."Object ID" }
                            $usersToRemoveGroup1 | ForEach-Object {
                                $userId = $_
                                $userName = $DetailsUsers | Where-Object { $_."Object ID" -eq $userId } | Select-Object -ExpandProperty "User Name"

                                Remove-MgGroupMemberByRef -GroupId $Group1.Id -DirectoryObjectId $userId -ErrorAction SilentlyContinue
                                # Add entry to the log
                                $logEntry = "{0} - [REMOVAL] {1} from the MFA_NotConfigured group" -f (Get-Date), $userName
                                Add-Content -Path $logFile -Value $logEntry
                                $sessionLogs += $logEntry
                            }

                            # Remove users who are present in the MFA_Authenticator+FIDO2 group but not in AuthenticatorFido2
                            $usersToRemoveGroup2 = $currentMembersGroup2 | Where-Object { $_ -notin $AuthenticatorFido2."Object ID" }
                            $usersToRemoveGroup2 | ForEach-Object {
                                $userId = $_
                                $userName = $DetailsUsers | Where-Object { $_."Object ID" -eq $userId } | Select-Object -ExpandProperty "User Name"

                                Remove-MgGroupMemberByRef -GroupId $Group2.Id -DirectoryObjectId $userId -ErrorAction SilentlyContinue
                                # Add entry to the log
                                $logEntry = "{0} - [REMOVAL] {1} from the MFA_Authenticator+FIDO2 group" -f (Get-Date), $userName
                                Add-Content -Path $logFile -Value $logEntry
                                $sessionLogs += $logEntry
                            }

                            # Remove users who are present in the MFA_FIDO2_Passwordless group but not in Fido2
                            $usersToRemoveGroup3 = $currentMembersGroup3 | Where-Object { $_ -notin $Fido2."Object ID" }
                            $usersToRemoveGroup3 | ForEach-Object {
                                $userId = $_
                                $userName = $DetailsUsers | Where-Object { $_."Object ID" -eq $userId } | Select-Object -ExpandProperty "User Name"

                                    Remove-MgGroupMemberByRef -GroupId $Group3.Id -DirectoryObjectId $userId -ErrorAction SilentlyContinue
                                    # Add entry to the log
                                    $logEntry = "{0} - [REMOVAL] {1} from the MFA_FIDO2_Passwordless group" -f (Get-Date), $userName
                                    Add-Content -Path $logFile -Value $logEntry
                                    $sessionLogs += $logEntry       
                            }

                            # Use -ErrorAction SilentlyContinue to ignore errors without interrupting the script.
                            # This is useful here due to the possible delay between the time
                            # the user changes are made in Azure AD and the time
                            # these changes are reflected in the Graph API.
                            # There can be some propagation time, especially during close actions
                            # such as removing and then adding a user.
                            # By using SilentlyContinue, the script continues to run
                            # even if the latest information has not yet fully propagated to the Graph API.

                            Write-Host "[Processing complete]" -ForegroundColor Green

                            Write-Host "`n`nOperation logs:"
                            if ($sessionLogs) {
                                $sessionLogs | ForEach-Object { Write-Host $_ }
                            } else {
                                Write-Host "No change!"
                            }
                            Write-Host "`n"
                            Pause

                          } # *** END Update Tool ***


                      "2" { # *** BEGIN Reset Tool ***
                            
                            Clear-Host
                            # Display the title
                            Write-Host $title2

                            # Initialize the variable containing the logs
                            $sessionLogs = @()

                            # Path of the log file in the same location as the script
                            $logFile = Join-Path -Path $PSScriptRoot -ChildPath "Log_ResetTool.log"
                            # Check if the file exists, otherwise create it
                            if (-not (Test-Path $logFile)) {
                                $null = New-Item -Path $logFile -ItemType File
                            }

                            Write-Host "Checking the installation of the Microsoft.Graph module...`n"
                            # Check if the Microsoft.Graph module is installed
                            if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
                                # If the module is not installed, install it
                                Write-Host "Installing the Microsoft.Graph module..."
                                Install-Module -Name Microsoft.Graph -Force
                            }

                            # By default, Microsoft Graph PowerShell commands target the v1.0 API version.
                            # Commands for APIs that are only available in beta version are not available in PowerShell by default.
                            # So we need to load the Beta profile to access all commands...
                            Select-MgProfile -Name Beta

                            Write-Host "Loading the Microsoft.Graph.Identity.Signins module..."
                            # Check if the Microsoft.Graph.Identity.Signins module is already loaded
                            if (-not (Get-Module -Name Microsoft.Graph.Identity.Signins)) {
                                # If the module is not already loaded, load the Microsoft.Graph.Identity.Signins module in PowerShell
                                Import-Module -Name Microsoft.Graph.Identity.Signins
                            }

                            Write-Host "Loading the Microsoft.Graph.Users.Actions module...`n"
                            # Check if the Microsoft.Graph.Users.Actions module is already loaded
                            if (-not (Get-Module -Name Microsoft.Graph.Users.Actions)) {
                                # If the module is not already loaded, load the Microsoft.Graph.Users.Actions module in PowerShell
                                Import-Module -Name Microsoft.Graph.Users.Actions
                            }

                            Write-Host "Connecting to the Graph API..."
                            # Establish a connection between the PowerShell session and the Microsoft Graph API with the necessary permissions.
                            Connect-MgGraph -Scopes "User.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All"
                            # User.ReadWrite.All --> Allows reading and writing to user profiles.
                            # UserAuthenticationMethod.ReadWrite.All --> Allows reading and writing to user authentication methods.

                            # Retrieve the email addresses of the users to process
                            $users = Read-Host -Prompt "`nUser Principal Names to reset (comma-separated)"

                            # Convert the string into an array
                            $userList = $users.Split(',')

                            foreach ($user in $userList) {

                                $user = $user.Trim()

                                Write-Host "`nAnalyzing user account ${user}...`n"
                                # Retrieve the user account to process
                                $AllMethods = Get-MgUserAuthenticationMethod -UserId $user

                                # Find all unique keys in AdditionalProperties
                                $allKeys = $AllMethods |
                                    ForEach-Object { $_.AdditionalProperties.Keys } |
                                    Sort-Object -Unique

                                # Create an array of all the details
                                $AllMethodDetails = foreach ($method in $AllMethods) {
                                    $details = @{}

                                    # Common properties for all types
                                    $details["Id"] = $method.Id
                                    $details["@odata.type"] = $method.AdditionalProperties["@odata.type"]

                                    # AdditionalProperties properties
                                    foreach ($key in $allKeys) {
                                        $details[$key] = $method.AdditionalProperties[$key]
                                    }

                                    New-Object -TypeName PSObject -Property $details
                                }

                                Write-Host "`nAuthentication method(s) found:"
                                # Display the details
                                $AllMethodDetails

                                Write-Host "`nRemoving all authentication methods..."
                                # Iterate through each method and remove it based on its type
                                foreach ($method in $AllMethods) {
                                    switch ($method.AdditionalProperties['@odata.type']) {
                                        '#microsoft.graph.emailAuthenticationMethod' {
                                            Remove-MgUserAuthenticationEmailMethod -UserId $user -EmailAuthenticationMethodId $method.Id
                                        }
                                        '#microsoft.graph.fido2AuthenticationMethod' {
                                            Remove-MgUserAuthenticationFido2Method -UserId $user -Fido2AuthenticationMethodId $method.Id
                                        }
                                        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                                            Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user -MicrosoftAuthenticatorAuthenticationMethodId $method.Id
                                        }
                                        '#microsoft.graph.phoneAuthenticationMethod' {
                                            Remove-MgUserAuthenticationPhoneMethod -UserId $user -PhoneAuthenticationMethodId $method.Id
                                        }
                                        '#microsoft.graph.softwareOathAuthenticationMethod' {
                                            Remove-MgUserAuthenticationSoftwareOathMethod -UserId $user -SoftwareOathAuthenticationMethodId $method.Id
                                        }
                                        '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
                                            Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user -TemporaryAccessPassAuthenticationMethodId $method.Id
                                        }
                                        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                                            Remove-MgUserAuthenticationWindowHelloForBusinessMethod -UserId $user -WindowsHelloForBusinessAuthenticationMethodId $method.Id
                                        }                                        
                                        '#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod' { 
                                            Remove-MgUserAuthenticationpasswordlessMicrosoftAuthenticatorMethod -UserId $user -passwordlessMicrosoftAuthenticatorAuthenticationMethodId $method.Id
                                        }
                                        '#microsoft.graph.passwordAuthenticationMethod' {}
                                        default {
                                            Write-Host "Unsupported method (remember to modify the script to add it ?!?): $($method.AdditionalProperties['@odata.type'])"
                                        }
                                    }
                                }

                                Write-Host "`nRevoking active tokens for ${user}..."

                                # Invalidate all tokens issued to applications as well as the user's session cookies.
                                # The user is then forced to sign in to all applications they previously consented to, regardless of the device.
                                # There may be a delay of a few minutes before the tokens are revoked.
                                Revoke-MgUserSignInSession -UserId $user

                                $logEntry = "{0} - [SUCCESS][CONF][RESET] {1}" -f (Get-Date), $user
                                Add-Content -Path $logFile -Value $logEntry
                                $sessionLogs += $logEntry

                                Write-Host "`n`n[Reset of ${user} completed]" -ForegroundColor Green
                            }

                            Write-Host "Operation logs:"
                            $sessionLogs | ForEach-Object { Write-Host $_ }
                            Write-Host "`n"
                            Pause

                          } # *** END Reset Tool ***


                      "3" { # *** BEGIN Passwordless Tool ***

                            Clear-Host
                            # Display the title
                            Write-Host $title3

                            # Initialize the variable containing the logs
                            $sessionLogs = @()

                            # Path of the log file in the same location as the script
                            $logFile = Join-Path -Path $PSScriptRoot -ChildPath "Log_PasswordlessTool.log"
                            # Check if the file exists, otherwise create it
                            if (-not (Test-Path $logFile)) {
                                $null = New-Item -Path $logFile -ItemType File
                            }

                            Write-Host "Checking the installation of the Microsoft.Graph module...`n"
                            # Check if the Microsoft.Graph module is installed
                            if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
                                # If the module is not installed, install it
                                Write-Host "Installing the Microsoft.Graph module..."
                                Install-Module -Name Microsoft.Graph -Force
                            }

                            # By default, Microsoft Graph PowerShell commands target the v1.0 API version.
                            # Commands for APIs that are only available in beta version are not available in PowerShell by default.
                            # So we need to load the Beta profile to access all commands...
                            Select-MgProfile -Name Beta

                            Write-Host "Loading the Microsoft.Graph.Identity.Signins module..."
                            # Check if the Microsoft.Graph.Identity.Signins module is already loaded
                            if (-not (Get-Module -Name Microsoft.Graph.Identity.Signins)) {
                                # If the module is not already loaded, load the Microsoft.Graph.Identity.Signins module in PowerShell
                                Import-Module -Name Microsoft.Graph.Identity.Signins
                            }

                            Write-Host "Loading the Microsoft.Graph.Users.Actions module...`n"
                            # Check if the Microsoft.Graph.Users.Actions module is already loaded
                            if (-not (Get-Module -Name Microsoft.Graph.Users.Actions)) {
                                # If the module is not already loaded, load the Microsoft.Graph.Users.Actions module in PowerShell
                                Import-Module -Name Microsoft.Graph.Users.Actions
                            }

                            Write-Host "Connecting to the Graph API..."
                            # Establish a connection between the PowerShell session and the Microsoft Graph API with the necessary permissions.
                            Connect-MgGraph -Scopes "User.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All"
                            # User.ReadWrite.All --> Allows reading and writing to user profiles.
                            # UserAuthenticationMethod.ReadWrite.All --> Allows reading and writing to user authentication methods.

                            # Retrieve the email addresses of the users to process
                            $users = Read-Host -Prompt "`nUser Principal Names to switch to Passwordless (Fido2 Only) (comma-separated)"

                            # Convert the string into an array
                            $userList = $users.Split(',')

                            foreach ($user in $userList) {
                                $user = $user.Trim()

                                Write-Host "`nAnalyzing account ${user}...`n"
                                # Retrieve the user account to process
                                $AllMethods = Get-MgUserAuthenticationMethod -UserId $user

                                # Find all unique keys in AdditionalProperties
                                $allKeys = $AllMethods |
                                    ForEach-Object { $_.AdditionalProperties.Keys } |
                                    Sort-Object -Unique

                                # Create an array of all the details
                                $AllMethodDetails = foreach ($method in $AllMethods) {
                                    $details = @{}

                                    # Common properties for all types
                                    $details["Id"] = $method.Id
                                    $details["@odata.type"] = $method.AdditionalProperties["@odata.type"]

                                    # AdditionalProperties properties
                                    foreach ($key in $allKeys) {
                                        $details[$key] = $method.AdditionalProperties[$key]
                                    }

                                    New-Object -TypeName PSObject -Property $details
                                }

                                # Check if the user is eligible for Passwordless
                                # (at least one FIDO2 key must have been configured via the initial MFA_Authenticator+FIDO2 setup)
                                $Group1 = Get-MgGroup -Filter "displayName eq 'MFA_Authenticator+FIDO2'"
                                $Group2 = Get-MgGroup -Filter "displayName eq 'MFA_FIDO2_Passwordless'"

                                $currentMembersGroup1 = Get-MgGroupMember -GroupId $Group1.Id -All | Select-Object -ExpandProperty Id # Microsoft Graph has a limit of 100 objects per request (pagination) -All bypasses pagination.
                                $currentMembersGroup2 = Get-MgGroupMember -GroupId $Group2.Id -All | Select-Object -ExpandProperty Id

                                # Retrieve the user's ID
                                $userDetails = Get-MgUser -Filter "userPrincipalName eq '$user'"
                                $userId = $userDetails.Id

                                # Check the user's presence in the groups
                                if ($currentMembersGroup1 -contains $userId) {
                                    # Check for the presence of fido2AuthenticationMethod
                                    $fido2AuthenticationMethodExists = $false
                                    foreach ($methodDetail in $AllMethodDetails) {
                                        if ($methodDetail.'@odata.type' -eq "#microsoft.graph.fido2AuthenticationMethod") {
                                            $fido2AuthenticationMethodExists = $true

                                            Write-Host "${user} is eligible for Passwordless`n"

                                            # Retrieve the user account to process
                                            $AllMethods = Get-MgUserAuthenticationMethod -UserId $user

                                            Write-Host "`nRemoving all authentication methods except Fido2Method:"
                                            # Iterate through each method and remove it based on its type
                                            foreach ($method in $AllMethods) {
                                                switch ($method.AdditionalProperties['@odata.type']) {
                                                    '#microsoft.graph.emailAuthenticationMethod' {
                                                        Remove-MgUserAuthenticationEmailMethod -UserId $user -EmailAuthenticationMethodId $method.Id
                                                    }
                                                    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                                                        Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user -MicrosoftAuthenticatorAuthenticationMethodId $method.Id
                                                    }
                                                    '#microsoft.graph.phoneAuthenticationMethod' {
                                                        Remove-MgUserAuthenticationPhoneMethod -UserId $user -PhoneAuthenticationMethodId $method.Id
                                                    }
                                                    '#microsoft.graph.softwareOathAuthenticationMethod' {
                                                        Remove-MgUserAuthenticationSoftwareOathMethod -UserId $user -SoftwareOathAuthenticationMethodId $method.Id
                                                    }
                                                    '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
                                                        Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user -TemporaryAccessPassAuthenticationMethodId $method.Id
                                                    }
                                                    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                                                        Remove-MgUserAuthenticationWindowHelloForBusinessMethod -UserId $user -WindowsHelloForBusinessAuthenticationMethodId $method.Id
                                                    }                                       
                                                    '#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod' { 
                                                        Remove-MgUserAuthenticationpasswordlessMicrosoftAuthenticatorMethod -UserId $user -passwordlessMicrosoftAuthenticatorAuthenticationMethodId $method.Id
                                                    }
                                                    '#microsoft.graph.passwordAuthenticationMethod' { } # Ignore, no need to remove it
                                                    default {
                                                        Write-Host "Unsupported method: $($method.AdditionalProperties['@odata.type'])"
                                                    }
                                                }
                                            }

                                            Write-Host "`nRevoking active tokens for ${user}"
                                            # Invalidate all tokens issued to applications as well as the user's session cookies.
                                            # The user is then forced to sign in to all applications they previously consented to, regardless of the device.
                                            # There may be a delay of a few minutes before the tokens are revoked.
                                            Revoke-MgUserSignInSession -UserId $user

                                            $logEntry = "{0} - [SUCCESS][CONF][PASSWORDLESS] {1}" -f (Get-Date), $user
                                            Add-Content -Path $logFile -Value $logEntry
                                            $sessionLogs += $logEntry

                                            Write-Host "[User ${user} is now configured in Passwordless mode]`n" -ForegroundColor Green

                                        }
                                    }

                                    if (!$fido2AuthenticationMethodExists) {

                                        $logEntry = "{0} - [ERROR][CONF][PASSWORDLESS][FIDO2_Key_Needed] {1}" -f (Get-Date), $user
                                        Add-Content -Path $logFile -Value $logEntry
                                        $sessionLogs += $logEntry

                                        Write-Host "The user ${user} must first configure at least one FIDO2 key.`n"
                                        Write-Host "Returning to the menu."
                                    }
                                }
                                elseif ($currentMembersGroup2 -contains $userId) {
                                    $logEntry = "{0} - [SUCCESS][CONF][ALREADY][PASSWORDLESS] {1}" -f (Get-Date), $user
                                    Add-Content -Path $logFile -Value $logEntry
                                    $sessionLogs += $logEntry
                                    Write-Host "The user ${user} is already configured in Passwordless mode."
                                    Write-Host "If there are any issues, run the Reset Tool."
                                    Write-Host "Returning to the menu."
                                }
                                else {
                                    $logEntry = "{0} - [ERROR][CONF][PASSWORDLESS][No MFA Or TAP Found] {1}" -f (Get-Date), $user
                                    Add-Content -Path $logFile -Value $logEntry
                                    $sessionLogs += $logEntry
                                    Write-Host "The user ${user} has no configured MFA methods or TAP!"
                                    Write-Host "Returning to the menu."
                                }
                            }

                            Write-Host "`n`nOperation logs:"
                            $sessionLogs | ForEach-Object { Write-Host $_ }
                            Write-Host "`n"
                            Pause 
                                                                          
                          } # *** END Passwordless Tool ***


                      "4" { # *** BEGIN TAP Manage Tool***
                
                            $exitTAPMenu = $false
                            do {
                                Clear-Host
                                # Display the title
                                Write-Host $title4

                                Write-Host "Checking the installation of the Microsoft.Graph module...`n"
                                # Check if the Microsoft.Graph module is installed
                                if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
                                    # If the module is not installed, install it
                                    Write-Host "Installing the Microsoft.Graph module..."
                                    Install-Module -Name Microsoft.Graph -Force
                                }

                                # By default, Microsoft Graph PowerShell commands target the v1.0 API version.
                                # Commands for APIs that are only available in the Beta version are not available in PowerShell by default.
                                # Therefore, load the Beta profile to have access to all commands...
                                Select-MgProfile -Name Beta

                                Write-Host "Loading the Microsoft.Graph.Identity.SignIns module..."
                                # Check if the Microsoft.Graph.Identity.SignIns module is already loaded
                                if (-not (Get-Module -Name Microsoft.Graph.Identity.SignIns)) {
                                    # If the module is not already loaded, load the Microsoft.Graph.Identity.SignIns module in PowerShell
                                    Import-Module -Name Microsoft.Graph.Identity.SignIns
                                }

                                Write-Host "Loading the Microsoft.Graph.Groups module..."
                                # Check if the Microsoft.Graph.Groups module is already loaded
                                if (-not (Get-Module -Name Microsoft.Graph.Groups)) {
                                    # If the module is not already loaded, load the Microsoft.Graph.Groups module in PowerShell
                                    Import-Module -Name Microsoft.Graph.Groups
                                }

                                Write-Host "Connecting to the Graph API..."
                                # Establish a connection between the PowerShell session and the Microsoft Graph API with the necessary permissions.
                                Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All"
                                # User.ReadWrite.All --> Allows reading and writing to user profiles.
                                # Group.ReadWrite.All --> Allows reading and writing to Groups.


                                Write-Host "`n`n1. Generate a TAP for one or multiple user(s) (export to .csv)"
                                Write-Host "2. Remove one or multiple TAPs`n"

                                Write-Host "3. Generate a TAP for all users (export to .csv)"
                                Write-Host "4. Remove all TAPs"

                                Write-Host "`n5. Back"

                                $TAPMenu = Read-Host -Prompt "`nYour choice"

                                switch ($TAPMenu) {
                                  '1' { # *** Start Generate TAP for one or multiple user(s) sub-menu ***

                                        Write-Host "`nTAP duration of validity:"
                                        Write-Host "1. 10 minutes"
                                        Write-Host "2. 1 hour"
                                        Write-Host "3. 1 day"
                                        Write-Host "4. 7 days"
                                        Write-Host "5. 30 days"
                                        $durationOption = Read-Host -Prompt "`nChoice (1, 2, 3, 4, or 5)"

                                        switch ($durationOption) {
                                            "1" { $lifetimeInMinutes = 10 } # 10 minutes
                                            "2" { $lifetimeInMinutes = 60 } # 1 hour
                                            "3" { $lifetimeInMinutes = 1440 } # 1 day
                                            "4" { $lifetimeInMinutes = 10080 } # 7 days
                                            "5" { $lifetimeInMinutes = 43200 } # 30 days
                                            Default { Write-Host "Invalid duration option"; return }
                                        }

                                        # Path of the *.csv file in the same location as the script
                                        $TAPcsvFile = Join-Path -Path $PSScriptRoot -ChildPath "TAP_SelectedUsers.csv"
                                        # Check if the file exists, if not, create it
                                        if (-not (Test-Path $TAPcsvFile)) {
                                            $null = New-Item -Path $TAPcsvFile -ItemType File
                                        }

                                        # Retrieve the user principal names of the users to process
                                        $usersInput = Read-Host -Prompt "`nUser principal names to generate TAP for (separated by commas)"

                                        # Check if $usersInput is null, if not, continue processing
                                        if ($null -ne $usersInput) {

                                            # Convert the string into an array
                                            $userList = $usersInput.Split(',')

                                            # Remove leading and trailing spaces from each username
                                            $userList = $userList | ForEach-Object { $_.Trim() }
                                        } else {
                                            Write-Host "`nNo users provided!"
                                            return
                                        }

                                        # Retrieve all users with their registration details
                                        $Uri = 'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails'
                                        $AllUsers = @()
                                        do {
                                            $result = Invoke-GraphRequest -Uri $Uri

                                            # Check if $result is null, if not, continue processing
                                            if ($null -ne $result) {
                                                $AllUsers += $result.Value
                                                $Uri = $result.'@odata.nextLink' # By default, Microsoft Graph API returns a maximum of 200 objects per page. OData allows querying as long as there are pages.
                                            } else {
                                                Write-Host "`nNo users found."
                                                return
                                            }
                                        } while ($Uri)

                                        # Store the details of the selected users in a variable
                                        $DetailsUsers = foreach ($user in $AllUsers) {
                                            if ($user.userPrincipalName -in $userList) {
                                                $details = @{
                                                    "Display Name"     = $user.userDisplayName  # --> Display name.
                                                    "User Principal Name" = $user.userPrincipalName  # --> User principal name.
                                                    "Object ID"        = $user.id # --> User object ID.
                                                }
                                                New-Object -TypeName PSObject -Property $details
                                            }
                                        }

                                        if ($DetailsUsers -eq $null) {
                                            Write-Host "`nNo user details found for the given usernames."
                                            return
                                        }

                                        Write-Host "`nGenerating a TAP for the selected users..."

                                        # Generate a TAP for selected users and export it to a CSV file
                                        $TAPUsers = foreach ($user in $DetailsUsers) {
                                            if ($null -ne $user) {
                                                $params = @{
                                                    startDateTime = [System.DateTime]::Now.ToLocalTime()
                                                    lifetimeInMinutes = $lifetimeInMinutes
                                                    isUsableOnce = $true
                                                }

                                              
                                                $TAP = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.'Object ID'.ToString() -BodyParameter $params -ErrorAction SilentlyContinue

                                                if ($null -ne $TAP) {
                                                    $startDateTime = $TAP.StartDateTime
                                                    if ($null -ne $startDateTime) {

                                                        # Retrieve the current time and the time zone difference
                                                        $currentTime = [System.DateTime]::Now
                                                        $utcTime = $currentTime.ToUniversalTime()
                                                        $timeDifference = $currentTime - $utcTime

                                                        # Add the time zone difference when calculating the end date
                                                        $endDateTime = $startDateTime.AddMinutes($TAP.LifetimeInMinutes).Add($timeDifference)

                                                        if ($null -ne $endDateTime) {
                                                            $lifetime = $endDateTime.ToString("dddd dd MMMM yyyy HH:mm:ss")
                                                            $userObj = New-Object PSObject
                                                            $userObj | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $user.'Display Name'
                                                            $userObj | Add-Member -MemberType NoteProperty -Name "User Principal Name" -Value $user.'User Principal Name'
                                                            $userObj | Add-Member -MemberType NoteProperty -Name "Single-Use TAP" -Value $TAP.TemporaryAccessPass
                                                            $userObj | Add-Member -MemberType NoteProperty -Name "Valid Until" -Value $lifetime
                                                            $userObj
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if ($TAPUsers -ne $null) {
                                            $TAPUsers | Where-Object { $_.'Display Name' -ne $null -and $_.'User Principal Name' -ne $null -and $_.'Single-Use TAP' -ne $null -and $_.'Valid Until' -ne $null } | Export-Csv -Path $TAPcsvFile -NoTypeInformation -Encoding UTF8
                                            Write-Host "`nTAP generated for all selected existing users and exported to TAP_SelectedUsers.csv file.`n" -ForegroundColor Green
                                            Pause
                                        } else {
                                            Write-Host "`nNo TAP generated. No information has been exported." -ForegroundColor Green
                                        }

                                      } # *** End Generate TAP for one or multiple user(s) sub-menu ***
                                                
                                  '2' { # *** Begin submenu Delete one or more TAPs ***

                                        Write-Host "`nDeleting TAPs for selected users..."

                                        # Retrieving the email addresses of users to process
                                        $usersInput = Read-Host -Prompt "`nUser Principal Names to delete TAP for (separated by commas)"

                                        # Convert the string to an array
                                        $userList = $usersInput.Split(',')
                                        # Trim spaces at the beginning and end of each username
                                        $userList = $userList | ForEach-Object { $_.Trim() }

                                        # Retrieve all users with their registration details
                                        $Uri = 'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails'
                                        $AllUsers = @()
                                        do {
                                            $result = Invoke-GraphRequest -Uri $Uri
                                            $AllUsers += $result.Value
                                            $Uri = $result.'@odata.nextLink' # By default, Microsoft Graph API returns a maximum of 200 objects per page. OData allows querying as long as there are pages.
                                        } while ($Uri)

                                        # Store the details of selected users in a variable
                                        $DetailsUsers = foreach ($user in $AllUsers) {
                                            if ($user.userPrincipalName -in $userList) {
                                                $details = @{
                                                    "Display Name"     = $user.userDisplayName  # --> Display name.
                                                    "User Principal Name" = $user.userPrincipalName  # --> User principal name.
                                                    "Object ID"          = $user.id # --> User object ID.
                                                }
                                                New-Object -TypeName PSObject -Property $details
                                            }
                                        }

                                        # Delete the TAPs for all selected users
                                        foreach ($user in $DetailsUsers) {
                                            $TAPs = Get-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.'Object ID'
                                            foreach ($TAP in $TAPs) {
                                                Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.'Object ID' -TemporaryAccessPassAuthenticationMethodId $TAP.Id
                                            }
                                        }
                                        Write-Host "`nTAPs for all selected users have been deleted.`n" -ForegroundColor Green
                                        Pause

                                    } # *** End submenu Delete one or more TAPs ***

                                  '3' { # *** Begin submenu Generate a TAP for all users ***

                                        Write-Host "`nTAP validity duration:"
                                        Write-Host "1. 10 minutes"
                                        Write-Host "2. 1 hour"
                                        Write-Host "3. 1 day"
                                        Write-Host "4. 7 days"
                                        Write-Host "5. 30 days"
                                        $durationOption = Read-Host -Prompt "`nEnter choice (1, 2, 3, 4, or 5)"

                                        # Path of the *.csv file in the same location as the script
                                        $TAPcsvFile = Join-Path -Path $PSScriptRoot -ChildPath "TAP_AllUsers.csv"
                                        # Check if the file exists, otherwise create it
                                        if (-not (Test-Path $TAPcsvFile)) {
                                            $null = New-Item -Path $TAPcsvFile -ItemType File
                                        }

                                        # Retrieve all users with their registration details
                                        $Uri = 'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails'
                                        $AllUsers = @()
                                        do {
                                            $result = Invoke-GraphRequest -Uri $Uri
                                            $AllUsers += $result.Value
                                            $Uri = $result.'@odata.nextLink' # By default, Microsoft Graph API returns a maximum of 200 objects per page. OData allows querying as long as there are pages.
                                        } while ($Uri)

                                        # Store the details of all users in a variable
                                        $DetailsUsers = foreach ($user in $AllUsers) {
                                            $details = @{
                                                "Display Name"     = $user.userDisplayName  # --> Display name.
                                                "User Principal Name" = $user.userPrincipalName  # --> User principal name.
                                                "Object ID"          = $user.id # --> User object ID.
                                            }
                                            New-Object -TypeName PSObject -Property $details
                                        }

                                        # Retrieve the IDs of members to exclude from processing
                                        $ExcludedUsers = $ListeExclus | ForEach-Object { (Get-MgUser -Filter "userPrincipalName eq '$_'").Id }

                                        # Filter out excluded users
                                        $FilteredUsers = foreach ($user in $DetailsUsers) {
                                            # Check if the user satisfies the filtering criteria
                                            if (($user.'Object ID' -notin $ExcludedUsers)) {
                                                $user
                                            }
                                        }

                                        Write-Host "`nGenerating a TAP for all users (excluding excluded users)..."
                                        # Generate a TAP for all users and export it to a CSV file
                                        $TAPUsers = foreach ($user in $FilteredUsers) {
                                            $params = @{
                                                startDateTime = [System.DateTime]::Now.ToLocalTime()
                                                lifetimeInMinutes = $lifetimeInMinutes
                                                isUsableOnce = $true
                                            }
                                               

                                            $TAP = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.'Object ID'.ToString() -BodyParameter $params -ErrorAction SilentlyContinue

                                            if ($null -ne $TAP) {
                                                $startDateTime = $TAP.StartDateTime
                                                if ($null -ne $startDateTime) {

                                                    # Get the current time and the time zone difference
                                                    $currentTime = [System.DateTime]::Now
                                                    $utcTime = $currentTime.ToUniversalTime()
                                                    $timeDifference = $currentTime - $utcTime

                                                    # Add the time zone difference when calculating the end date
                                                    $endDateTime = $startDateTime.AddMinutes($TAP.LifetimeInMinutes).Add($timeDifference)

                                                    if ($null -ne $endDateTime) {
                                                        $lifetime = $endDateTime.ToString("dddd dd MMMM yyyy HH:mm:ss")
                                                        $userObj = New-Object PSObject
                                                        $userObj | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $user.'Display Name'
                                                        $userObj | Add-Member -MemberType NoteProperty -Name "User Principal Name" -Value $user.'User Principal Name'
                                                        $userObj | Add-Member -MemberType NoteProperty -Name "Single-use TAP" -Value $TAP.TemporaryAccessPass
                                                        $userObj | Add-Member -MemberType NoteProperty -Name "Valid until" -Value $lifetime
                                                        $userObj
                                                    }
                                                }
                                            }
                                        }

                                        # Export the results to a CSV file
                                        $TAPUsers | Where-Object { $_.'Display Name' -ne $null -and $_.'User Principal Name' -ne $null -and $_.'Single-Use TAP' -ne $null -and $_.'Valid Until' -ne $null } | Export-Csv -Path $TAPcsvFile -NoTypeInformation -Encoding UTF8
                                        Write-Host "`nTAP generated for all users and exported to TAP_AllUsers.csv file.`n" -ForegroundColor Green
                                        Pause

                                      } # *** End submenu Generate a TAP for all users ***

                                  '4' { # *** Begin submenu Delete all TAPs ***

                                        Write-Host "`nDeleting all user TAPs..."

                                        # Retrieve all users with their registration details
                                        $Uri = 'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails'
                                        $AllUsers = @()
                                        do {
                                            $result = Invoke-GraphRequest -Uri $Uri
                                            $AllUsers += $result.Value
                                            $Uri = $result.'@odata.nextLink' # By default, Microsoft Graph API returns a maximum of 200 objects per page. OData allows querying as long as there are pages.
                                        } while ($Uri)

                                        # Store the details of all users in a variable
                                        $DetailsUsers = foreach ($user in $AllUsers) {
                                            $details = @{
                                                "Display Name"     = $user.userDisplayName  # --> Display name.
                                                "User Principal Name" = $user.userPrincipalName  # --> User principal name.
                                                "Object ID"          = $user.id # --> User object ID.
                                            }
                                            New-Object -TypeName PSObject -Property $details
                                        }

                                        # Retrieve the IDs of members to exclude from processing
                                        $ExcludedUsers = $ListeExclus | ForEach-Object { (Get-MgUser -Filter "userPrincipalName eq '$_'").Id }


                                        # Filter out excluded users
                                        $FilteredUsers = foreach ($user in $DetailsUsers) {
                                            # Check if the user satisfies the filtering criteria
                                            if (($user.'Object ID' -notin $ExcludedUsers)) {
                                                $user
                                            }
                                        }

                                        # Delete the TAPs for all users
                                        foreach ($user in $FilteredUsers) {
                                            $TAPs = Get-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.'Object ID'
                                            foreach ($TAP in $TAPs) {
                                                Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId $user.'Object ID' -TemporaryAccessPassAuthenticationMethodId $TAP.Id
                                            }
                                        }
                                        Write-Host "`nAll user TAPs have been deleted.`n" -ForegroundColor Green
                                        Pause

                                      } # *** End submenu Delete all TAPs ***
                                    
                                  '5' { # *** Begin submenu Return ***                               
                                        $exitTAPMenu = $True
                                      } # *** End submenu Return ***                                    
                                            
                              default { # *** Begin submenu Default ***
                                        Write-Host "Oopsie! Incorrect choice. Dive into the sea of available options and give it another go!"                                  
                                        Start-Sleep -Seconds 1                               
                                        } # *** End submenu Default ***

                                                  }
                               } while ($exitTAPMenu -eq $false)

                          } # *** END TAP Manage Tool ***


                      "5" { # *** Quit ***
                            Disconnect-MgGraph
                            Clear-Host
                            exit
                          } # *** END Quit ***


                      "99" { # *** BEGIN AutoConf Script ***

                      $confirmation = Read-Host "Are you sure you want to run the AutoConf script? (y/n)"
                      if ($confirmation -eq 'y') {
   
                            # Automation script for configuration and installation 
                            # of the essential prerequisites for the operation of MfaPasslessPizazz
   
                            Clear-Host
                            # Display the title
                            Write-Host $title5    
       
               
                            # Check if the Microsoft.Graph module is installed
                            if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
                            # If the module is not installed, install it
                            Write-Host "`nInstalling the Microsoft.Graph module..."
                            Install-Module -Name Microsoft.Graph -Force
                            }

                            # By default, Microsoft Graph PowerShell commands target the v1.0 API version.
                            # Commands for APIs that are only available in beta version are not available in PowerShell by default.
                            # We need to load the Beta profile to access all the commands...
                            Select-MgProfile -Name Beta

                            Write-Host "Loading the Microsoft.Graph.Identity module..."
                            # Check if the Microsoft.Graph.Identity module is already loaded
                            if (-not (Get-Module -Name Microsoft.Graph.Identity.SignIns)) {
                            # If the module is not already loaded, load the Microsoft.Graph.Identity module in PowerShell
                            Import-Module -Name Microsoft.Graph.Identity.SignIns
                            }

                            Write-Host "Connecting to the Graph API..."
                            # Establish a connection between the PowerShell session and the Microsoft Graph API with the necessary permissions.
                            Connect-MgGraph -Scopes "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Application.Read.All", "Policy.ReadWrite.AuthenticationMethod"



                            Write-Host "`nConfiguring Security Groups..."
                            # https://portal.azure.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/AllGroups
                            # https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.groups/new-mggroup?view=graph-powershell-1.0
                            #******************************************************
                            #********** CONFIGURATION OF SECURITY GROUPS **********
                            #******************************************************

                            # Search for existing groups using their display name
                            $Group1 = Get-MgGroup -Filter "displayName eq 'MFA_NotConfigured'"
                            $Group2 = Get-MgGroup -Filter "displayName eq 'MFA_Authenticator+FIDO2'"
                            $Group3 = Get-MgGroup -Filter "displayName eq 'MFA_FIDO2_Passwordless'"

                            # Verify existence of group 1. If it does not exist, the script creates it.
                            if (-not $Group1) {
                                # Parameters for creating group 1
                                $newGroupParams = @{
                                    DisplayName     = "MFA_NotConfigured"
                                    Description     = "Group for users without MFA configuration"
                                    MailEnabled     = $false
                                    SecurityEnabled = $true
                                    MailNickname    = "MFA_NotConfigured"
                                }
                                # Creating group 1
                                $Group1 = New-MgGroup @newGroupParams
                            }

                            # Verify existence of group 2. If it does not exist, the script creates it.
                            if (-not $Group2) {
                                # Parameters for creating group 2
                                $newGroupParams = @{
                                    DisplayName     = "MFA_Authenticator+FIDO2"
                                    Description     = "Group for users with MFA Authenticator(push+password) or FIDO2 Passwordless"
                                    MailEnabled     = $false
                                    SecurityEnabled = $true
                                    MailNickname    = "MFA_Authenticator+FIDO2"
                                }
                                # Creating group 2
                                $Group2 = New-MgGroup @newGroupParams
                            }

                            # Verify existence of group 3. If it does not exist, the script creates it.
                            if (-not $Group3) {
                                # Parameters for creating group 3
                                $newGroupParams = @{
                                    DisplayName     = "MFA_FIDO2_Passwordless"
                                    Description     = "Group for users with FIDO2 Passwordless"
                                    MailEnabled     = $false
                                    SecurityEnabled = $true
                                    MailNickname    = "MFA_FIDO2_Passwordless"
                                }
                                # Creating group 3
                                $Group3 = New-MgGroup @newGroupParams
                            }






                            Write-Host "`nConfiguring Safe Public IP list...(optional)"
                            # https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/NamedLocations
                            # https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-namedlocations?view=graph-rest-1.0&tabs=powershell
                            #*****************************************************************
                            #********** CONFIGURATION OF 'Safe Public IPs' LOCATION **********
                            #*****************************************************************

                            # Named location name
                            $displayName = "Safe Public IPs"

                            # Input of IPv4 addresses
                            Write-Host "Enter your Safe Public IPv4 addresses (81.82.83.84/28, 85.86.87.88/29)"
                            $ipv4Addresses = Read-Host -Prompt "`Your IPv4 addresses (comma-separated)"

                            # Input of IPv6 addresses
                            Write-Host "Enter your Safe Public IPv6 addresses (2001:0:9d38:90d6:0:0:0:0/63, 2001:db8::8a2e:370:7334/64)"
                            $ipv6Addresses = Read-Host -Prompt "`Your IPv6 addresses (comma-separated)"

                            # Initializes the variable that will contain the ID of the named location
                            $ListSafePublicIPs = $null

                            # Processing of IPv4 addresses
                            $ipv4Array = @()
                            if ($ipv4Addresses.Trim() -ne "") {
                                if ($ipv4Addresses.Contains(",")) {
                                    # If several IPv4 addresses are provided, we separate them and transform them into a hash table
                                    $ipv4Array = $ipv4Addresses.Split(",") | ForEach-Object {
                                        @{
                                            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                                            cidrAddress = $_.Trim()
                                        }
                                    }
                                } else {
                                    # If only one IPv4 address is provided, we transform it directly into a hash table
                                    $ipv4Array = @(
                                        @{
                                            "@odata.type" = "#microsoft.graph.iPv4CidrRange"
                                            cidrAddress = $ipv4Addresses.Trim()
                                        }
                                    )
                                }
                            }

                            # Processing of IPv6 addresses
                            $ipv6Array = @()
                            if ($ipv6Addresses.Trim() -ne "") {
                                if ($ipv6Addresses.Contains(",")) {
                                    # If several IPv6 addresses are provided, we separate them and transform them into a hash table
                                    $ipv6Array = $ipv6Addresses.Split(",") | ForEach-Object {
                                        @{
                                            "@odata.type" = "#microsoft.graph.iPv6CidrRange"
                                            cidrAddress = $_.Trim()
                                        }
                                    }
                                } else {
                                    # If only one IPv6 address is provided, we transform it directly into a hash table
                                    $ipv6Array = @(
                                        @{
                                            "@odata.type" = "#microsoft.graph.iPv6CidrRange"
                                            cidrAddress = $ipv6Addresses.Trim()
                                        }
                                    )
                                }
                            }

                            # Concatenates the IPv4 and IPv6 addresses into a single hash table
                            $ipRanges = @()
                            if($ipv4Array.GetType().BaseType.Name -eq "Array") {
                                $ipRanges += $ipv4Array
                            }
                            if($ipv6Array.GetType().BaseType.Name -eq "Array") {
                                $ipRanges += $ipv6Array
                            }

                            # Create the parameters of the named location
                            $params = @{
                                "@odata.type" = "#microsoft.graph.ipNamedLocation"
                                displayName = $displayName
                                isTrusted = $true
                                ipRanges = $ipRanges
                            }

                            # Search for existing named location
                            $existingLocation = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.displayName -eq $displayName }

                            # Update or create the named location
                            if ($null -ne $existingLocation) {
                                # If the named location already exists
                                if ($params.ipRanges.Count -gt 0) {
                                    # If at least one valid IP address is provided, update the named location
                                    Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $existingLocation.Id -BodyParameter $params
                                    $ListSafePublicIPs = $existingLocation.Id
                                    Write-Host "The existing 'Safe Public IPs' list has been updated."
                                } else {
                                    # If no valid IP address is provided, do nothing
                                    Write-Host "No update made as no valid IP address was provided."
                                }
                            } else {
                                # If the named location does not yet exist
                                if ($params.ipRanges.Count -gt 0) {
                                    # If at least one valid IP address is provided, create a new named location
                                    $newLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $params
                                    $ListSafePublicIPs = $newLocation.Id
                                    Write-Host "The 'Safe Public IPs' list has been created."
                                } else {
                                    # If no valid IP address is provided, do nothing
                                    Write-Host "No 'Safe Public IPs' list has been created as no valid IP address was provided."
                                }
                            }





                            Write-Host "`nConfiguring Authentication Methods Settings..."
                            # https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AuthMethodsSettings
                            # https://learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-update?view=graph-rest-1.0&tabs=powershell
                            # Handy command to list all active settings:
                            # Get-MgPolicyAuthenticationMethodPolicy | ConvertTo-Json -Depth 100
                            #*********************************************************************
                            #********** CONFIGURATION OF AUTHENTICATION METHODS SETTINGS *********
                            #*********************************************************************

                            $Params = @{
                                SystemCredentialPreferences = @{
                                    ExcludeTargets = @()
                                    IncludeTargets = @(
                                        @{
                                            Id = "all_users"
                                            TargetType = "group"
                                        }
                                    )
                                    State = "enabled"
                                }
                                    reportSuspiciousActivitySettings = @{
                                        state = "enabled"
                                        voiceReportingCode = 0
                                        includeTarget = @{
                                            id = "all_users"
                                            targetType = "group"
                                        }
                                    }               
                            }

                            Update-MgPolicyAuthenticationMethodPolicy -BodyParameter $params





                            Write-Host "`nConfiguring Authentication Strength Points..."
                            # https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/AuthStrengths
                            # https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-list-policies?view=graph-rest-1.0&tabs=powershell
                            #*********************************************************************
                            #********** CONFIGURATION OF AUTHENTICATION STRENGTH POINTS **********
                            #*********************************************************************

                            # Initializes the settings for authentication policies
                            $policies = @(
                                @{
                                    "DisplayName" = "Authenticator Push + FIDO2"
                                    "Description" = "Allows the user to benefit from Hybrid MFA/Passwordless access"
                                    "AllowedCombinations" = @("temporaryAccessPassOneTime","password,microsoftAuthenticatorPush", "fido2")
                                },
                                @{
                                    "DisplayName" = "FIDO2 Passwordless"
                                    "Description" = "Allows the user to benefit from Full Passwordless access"
                                    "AllowedCombinations" = @("temporaryAccessPassOneTime", "fido2")
                                }
                            )

                            # Loops through each policy
                            foreach ($policy in $policies) {
                                $existingPolicy = Get-MgPolicyAuthenticationStrengthPolicy | Where-Object { $_.DisplayName -eq $policy.DisplayName }

                                $params = @{
                                    "@odata.type" = "#microsoft.graph.authenticationStrengthPolicy"
                                    displayName = $policy.DisplayName
                                    description = $policy.Description
                                }

                                if ($null -ne $existingPolicy) {
                                    # Existing policy found, update
                                    Update-MgPolicyAuthenticationStrengthPolicy -AuthenticationStrengthPolicyId $existingPolicy.Id -BodyParameter $params | Out-Null

                                    # Update allowed authentication method combinations
                                    $combinationParams = @{ allowedCombinations = $policy.AllowedCombinations }
                                    Update-MgPolicyAuthenticationStrengthPolicyAllowedCombination -AuthenticationStrengthPolicyId $existingPolicy.Id -BodyParameter $combinationParams | Out-Null
                                } else {
                                    # No existing policy found, create a new one
                                    $params.allowedCombinations = $policy.AllowedCombinations
                                    New-MgPolicyAuthenticationStrengthPolicy -BodyParameter $params | Out-Null
                                }
                            }
                            $AuthenticatorPushFIDO2ID = (Get-MgPolicyAuthenticationStrengthPolicy | Where-Object { $_.DisplayName -eq "Authenticator Push + FIDO2" }).Id
                            $FIDO2PasswordlessID = (Get-MgPolicyAuthenticationStrengthPolicy | Where-Object { $_.DisplayName -eq "FIDO2 Passwordless" }).Id





                            Write-Host "`nConfiguring Authentication Methods..."
                            # https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods
                            # https://learn.microsoft.com/en-us/graph/api/microsoftauthenticatorauthenticationmethodconfiguration-get?view=graph-rest-1.0&tabs=powershell
                            #*************************************************************
                            #********** CONFIGURATION OF AUTHENTICATION METHODS **********
                            #*************************************************************

                            # Retrieve all authentication policies
                            $policies = Get-MgPolicyAuthenticationMethodPolicy

                            # Parcoure les politiques et trouver les méthode d'authentification
                            $fido2Method = $policies.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Fido2" }
                            $MicrosoftAuthenticatorMethod = $policies.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "MicrosoftAuthenticator" }
                            $TemporaryAccessPassMethod = $policies.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "TemporaryAccessPass" }
                            $SmsMethod = $policies.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Sms" }
                            $SoftwareOathMethod = $policies.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "SoftwareOath" }
                            $EmailMethod = $policies.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Email" }
                            $VoiceMethod = $policies.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Voice" }
                            $X509CertificateMethod = $policies.AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "X509Certificate" }


                            # Verifies and sets the FIDO2 authentication method policy
                            # # https://blog.workinghardinit.work/2021/11/01/fido2-aaguid-lists/   
                            # Handy command to list all active settings:
                            # Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Fido2" | ConvertTo-Json -Depth 100
                            if ($fido2Method) {

                                    # Update settings for FIDO2 Security Key
                                    $params = @{
                                        "@odata.type" = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
                                        state = "enabled"
                                        isAttestationEnforced = "true"
                                        isSelfServiceRegistrationAllowed = "true"
                                        keyRestrictions = @{
                                            isEnforced = "true"
                                            enforcementType = "allow"
                                            aaGuids = @(
                                                "2c0df832-92de-4be1-8412-88a8f074df4a",
                                                "8c97a730-3f7b-41a6-87d6-1e9b62bda6f0",
                                                "310b2830-bd4a-4da5-832e-9a0dfc90abf2",
                                                "6e22415d-7fdf-4ea4-8a0c-dd60c4249b9d",
                                                "833b721a-ff5f-4d00-bb2e-bdda3ec01e29",
                                                "ee041bce-25e5-4cdb-8f86-897fd6418464",
                                                "77010bd7-212a-4fc9-b236-d2ca5e9d4084",
                                                "b6ede29c-3772-412c-8a78-539c1f4c62d2",
                                                "77010bd7-212a-4fc9-b236-d2ca5e9d4084",
                                                "b6ede29c-3772-412c-8a78-539c1f4c62d2",
                                                "cb69481e-8ff7-4039-93ec-0a2729a154a8",
                                                "ee882879-721c-4913-9775-3dfcce97072a",
                                                "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
                                                "2fc0579f-8113-47ea-b116-bb5a8db9202a",
                                                "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd",
                                                "cb69481e-8ff7-4039-93ec-0a2729a154a8",
                                                "ee882879-721c-4913-9775-3dfcce97072a",
                                                "73bb0cd4-e502-49b8-9c6f-b59445bf720b",
                                                "cb69481e-8ff7-4039-93ec-0a2729a154a8",
                                                "ee882879-721c-4913-9775-3dfcce97072a",
                                                "73bb0cd4-e502-49b8-9c6f-b59445bf720b",
                                                "cb69481e-8ff7-4039-93ec-0a2729a154a8",
                                                "ee882879-721c-4913-9775-3dfcce97072a",
                                                "73bb0cd4-e502-49b8-9c6f-b59445bf720b",
                                                "2fc0579f-8113-47ea-b116-bb5a8db9202a",
                                                "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd",
                                                "c5ef55ff-ad9a-4b9f-b580-adebafe026d0",
                                                "85203421-48f9-4355-9bc8-8a53846e5083",
                                                "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
                                                "b92c3f9a-c014-4056-887f-140a2501163b",
                                                "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73",
                                                "149a2021-8ef6-4133-96b8-81f8d5b7f1f5",
                                                "149a2021-8ef6-4133-96b8-81f8d5b7f1f5",
                                                "2fc0579f-8113-47ea-b116-bb5a8db9202a",
                                                "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73",
                                                "73bb0cd4-e502-49b8-9c6f-b59445bf720b",
                                                "85203421-48f9-4355-9bc8-8a53846e5083",
                                                "b92c3f9a-c014-4056-887f-140a2501163b",
                                                "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd",
                                                "c5ef55ff-ad9a-4b9f-b580-adebafe026d0",
                                                "cb69481e-8ff7-4039-93ec-0a2729a154a8",
                                                "ee882879-721c-4913-9775-3dfcce97072a",
                                                "f8a011f3-8c0a-4d15-8006-17111f9edc7d",
                                                "fa2b99dc-9e39-4257-8f92-4a30d23c4118",
                                                "95442b2e-f15e-4def-b270-efb106facb4e",
                                                "87dbc5a1-4c94-4dc8-8a47-97d800fd1f3c",
                                                "da776f39-f6c8-4a89-b252-1d86137a46ba",
                                                "e3512a8a-62ae-11ea-bc55-0242ac130003"

                                            )
                                        }
                                         includeTargets = @(
                                                @{
                                                    targetType = "group"
                                                    id = $Group1.id
                                                    isRegistrationRequired = $false
                                                },
                                                @{
                                                    targetType = "group"
                                                    id = $Group2.id
                                                    isRegistrationRequired = $false
                                                },
                                                @{
                                                    targetType = "group"
                                                    id = $Group3.id
                                                    isRegistrationRequired = $false
                                                }
                                            )
                                    }

                                    # Updates the FIDO2 authentication method
                                    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Fido2" -BodyParameter $params | Out-Null

                            } else {
                                # Nothing
                            }


                            # Verifies and sets the Microsoft Authenticator authentication method policy
                            # Handy command to list all active settings:
                            # Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "MicrosoftAuthenticator" | ConvertTo-Json -Depth 100
                            if ($MicrosoftAuthenticatorMethod) {

                            $params = @{
                                "@odata.type" = "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration"
                                State = "enabled"
                                isSoftwareOathEnabled = $false
                                includeTargets = @(
                                    @{
                                        targetType = "group"
                                        id = $Group1.id
                                        isRegistrationRequired = $false
                                        authenticationMode = "any"
                                    },
                                    @{
                                        targetType = "group"
                                        id = $Group2.id
                                        isRegistrationRequired = $false
                                        authenticationMode = "any"
                                    },
                                    @{
                                        targetType = "group"
                                        id = $Group3.id
                                        isRegistrationRequired = $false
                                        authenticationMode = "any"
                                    }
                                )
                                featureSettings = @{
                                    companionAppAllowedState = @{
                                        state = "enabled"
                                        includeTarget = @{
                                            targetType = "group"
                                            id = "all_users"
                                        }
                                        excludeTarget = @{
                                            targetType = "group"
                                            id = "00000000-0000-0000-0000-000000000000"
                                        }
                                    }       
                                    displayAppInformationRequiredState = @{
                                        state = "enabled"
                                        includeTarget = @{
                                            targetType = "group"
                                            id = "all_users"
                                        }
                                        excludeTarget = @{
                                            targetType = "group"
                                            id = "00000000-0000-0000-0000-000000000000"
                                        }
                                    }
                                    displayLocationInformationRequiredState = @{
                                        state = "enabled"
                                        includeTarget = @{
                                            targetType = "group"
                                            id = "all_users"
                                        }
                                        excludeTarget = @{
                                            targetType = "group"
                                            id = "00000000-0000-0000-0000-000000000000"
                                        }
                                    }
                                }
                            }
      
                            Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "MicrosoftAuthenticator" -BodyParameter $params | Out-Null

                            } else {
                                # Nothing
                            }


                            # Verifies and sets the Temporary Access Pass authentication method policy
                            # Handy command to list all active settings:
                            # Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "TemporaryAccessPass" | ConvertTo-Json -Depth 100
                            if ($TemporaryAccessPassMethod) {

                            $params = @{
                                "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
                                state = "enabled"
                                defaultLifetimeInMinutes = 10
                                defaultLength = 12
                                minimumLifetimeInMinutes = 10
                                maximumLifetimeInMinutes = 43200
                                isUsableOnce = $true
                                includeTargets = @(
                                    @{
                                        targetType = "group"
                                        id = $Group1.id
                                        isRegistrationRequired = $false
                                    },
                                    @{
                                        targetType = "group"
                                        id = $Group2.id
                                        isRegistrationRequired = $false
                                    },
                                    @{
                                        targetType = "group"
                                        id = $Group2.id
                                        isRegistrationRequired = $false
                                    }
                                )
                            }

                            Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "TemporaryAccessPass" -BodyParameter $params | Out-Null

                            } else {
                                # Nothing
                            }


                            # Verifies and sets the Sms authentication method policy
                            # Handy command to list all active settings:
                            # Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Sms" | ConvertTo-Json -Depth 100
                            if ($SmsMethod) {

                            $params = @{
                                "@odata.type" = "#microsoft.graph.smsAuthenticationMethodConfiguration"
                                state = "disabled"
                                includeTargets = @(
                                    @{
                                        targetType = "group"
                                        id = "all_users"
                                        isRegistrationRequired = $false
                                        isUsableForSignIn = $true
                                    }
                                )
                            }

                            Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Sms" -BodyParameter $params | Out-Null

                            } else {
                                # Nothing
                            }


                            # Verifies and sets the SoftwareOath authentication method policy
                            # Handy command to list all active settings:
                            # Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "SoftwareOath" | ConvertTo-Json -Depth 100
                            if ($SoftwareOathMethod) {

                            $params = @{
                                "@odata.type" = "#microsoft.graph.softwareOathAuthenticationMethodConfiguration"
                                state = "disabled"
                                includeTargets = @(
                                    @{
                                        targetType = "group"
                                        id = "all_users"
                                        isRegistrationRequired = $false
                                    }
                                )
                            }

                            Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "SoftwareOath" -BodyParameter $params | Out-Null

                            } else {
                                # Nothing
                            }


                            # Verifies and sets the Email authentication method policy 
                            # Handy command to list all active settings:
                            # Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Email" | ConvertTo-Json -Depth 100
                            if ($EmailMethod) {

                            $params = @{
                                "@odata.type" = "#microsoft.graph.emailAuthenticationMethodConfiguration"
                                state = "disabled"
                                allowExternalIdToUseEmailOtp = "default"
                                includeTargets = @(
                                    @{
                                        targetType = "group"
                                        id = "all_users"
                                        isRegistrationRequired = $false
                                    }
                                )
                            }

                            Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Email" -BodyParameter $params | Out-Null

                            } else {
                                # Nothing
                            }


                            # Verifies and sets the Voice authentication method policy 
                            # Handy command to list all active settings:
                            # Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Voice" | ConvertTo-Json -Depth 100
                            if ($VoiceMethod) {

                            $params = @{
                                "@odata.type" = "#microsoft.graph.voiceAuthenticationMethodConfiguration"
                                state = "disabled"
                                isOfficePhoneAllowed = $false
                                includeTargets = @(
                                    @{
                                        targetType = "group"
                                        id = "all_users"
                                        isRegistrationRequired = $false
                                    }
                                )
                            }

                            Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "Voice" -BodyParameter $params | Out-Null

                            } else {
                                # Nothing
                            }


                            # Verifies and sets the X509Certificate authentication method policy
                            # Handy command to list all active settings:
                            # Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "X509Certificate" | ConvertTo-Json -Depth 100
                            if ($X509CertificateMethod) {

                            $params = @{
                                "@odata.type" = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
                                state = "disabled"
                                certificateUserBindings = @(
                                    @{
                                        x509CertificateField = "PrincipalName"
                                        userProperty = "onPremisesUserPrincipalName"
                                        priority = 1
                                        trustAffinityLevel = "low"
                                    },
                                    @{
                                        x509CertificateField = "RFC822Name"
                                        userProperty = "userPrincipalName"
                                        priority = 2
                                        trustAffinityLevel = "low"
                                    }
                                )
                                authenticationModeConfiguration = @{
                                    x509CertificateAuthenticationDefaultMode = "x509CertificateSingleFactor"
                                    rules = @()
                                }
                                includeTargets = @(
                                    @{
                                        targetType = "group"
                                        id = "all_users"
                                        isRegistrationRequired = $false
                                    }
                                )
                            }

                            Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId "X509Certificate" -BodyParameter $params | Out-Null

                            } else {
                               # Nothing
                            }





                            Write-Host "`nConfiguring Conditional Access Policies..."
                            # https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies
                            # https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-policies?view=graph-rest-beta&tabs=powershell
                            #******************************************************************
                            #********** CONFIGURATION OF CONDITIONAL ACCESS POLICIES **********
                            #******************************************************************

                            # Check and set the NotConfigured conditional access policy
                            # Handy command to list all active settings
                            # Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq "NotConfigured" } | ConvertTo-Json -Depth 100

                            # Define the name of the conditional access policy
                            $displayName = "NotConfigured"

                            # Retrieve the conditional access policy that has the name defined above.
                            $conditionalAccessPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq $displayName }

                            # Prepare the parameters for the conditional access policy
                            $Params = @{
                                DisplayName = $displayName
                                State = "enabled"
                                Conditions = @{
                                    Applications = @{
                                        IncludeApplications = @("All")
                                    }
                                    ClientAppTypes = @("all")       
                                    Users = @{
                                        IncludeGroups = @($Group1.id)
                                    }
                                }
                                GrantControls = @{
                                    Operator = "OR"
                                    BuiltInControls = @()
                                    AuthenticationStrength = @{
                                        Id = $AuthenticatorPushFIDO2ID
                                        PolicyType = "custom"
                                        RequirementsSatisfied = "mfa"
                                    }
                                }
                                SessionControls = @{
                                        PersistentBrowser = @{
                                            IsEnabled = $true
                                            Mode = "never"
                                        }
                                    }
                            }

                            # If the conditional access policy already exists, delete it then recreate it (too risky to update the parameters!)
                            if ($conditionalAccessPolicy) {
                                Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $conditionalAccessPolicy.Id
                                New-MgIdentityConditionalAccessPolicy -BodyParameter $Params | Out-Null
                            # Otherwise, create a new conditional access policy
                            } else {
                                New-MgIdentityConditionalAccessPolicy -BodyParameter $Params | Out-Null
                            }


                            # Check and set the PasswordAuthenticatorPush+FIDO2 conditional access policy
                            # Handy command to list all active settings
                            # Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq "PasswordAuthenticatorPush+FIDO2" } | ConvertTo-Json -Depth 100

                            # Define the name of the conditional access policy
                            $displayName = "PasswordAuthenticatorPush+FIDO2"

                            # Retrieve the conditional access policy that has the name defined above.
                            $conditionalAccessPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq $displayName }

                            # Prepare the parameters for the conditional access policy
                            if ($ListSafePublicIPs -eq $null) {
                                $Params = @{
                                    DisplayName = $displayName
                                    State = "enabled"
                                    Conditions = @{
                                        Applications = @{
                                            IncludeApplications = @("All")
                                        }
                                        ClientAppTypes = @("all")
                                        Users = @{
                                            IncludeGroups = @($Group2.id)
                                        }
                                    }
                                    GrantControls = @{
                                        Operator = "OR"
                                        BuiltInControls = @()
                                        AuthenticationStrength = @{
                                            Id = $AuthenticatorPushFIDO2ID
                                            PolicyType = "custom"
                                            RequirementsSatisfied = "mfa"
                                        }
                                    }
                                }
                            } else {
                                $Params = @{
                                    DisplayName = $displayName
                                    State = "enabled"
                                    Conditions = @{
                                        Applications = @{
                                            IncludeApplications = @("All")
                                        }
                                        ClientAppTypes = @("all")
                                        Users = @{
                                            IncludeGroups = @($Group2.id)
                                        }
		                            locations = @{
			                            includeLocations = @("All")
			                            excludeLocations = @($ListSafePublicIPs)
		                            }
                                    }
                                    GrantControls = @{
                                        Operator = "OR"
                                        BuiltInControls = @()
                                        AuthenticationStrength = @{
                                            Id = $AuthenticatorPushFIDO2ID
                                            PolicyType = "custom"
                                            RequirementsSatisfied = "mfa"
                                        }
                                    }
                                }
                            }

                            # If the conditional access policy already exists, delete it then recreate it (too risky to update the parameters!)
                            if ($conditionalAccessPolicy) {
                                Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $conditionalAccessPolicy.Id
                                New-MgIdentityConditionalAccessPolicy -BodyParameter $Params | Out-Null
                            # Otherwise, create a new conditional access policy
                            } else {
                                New-MgIdentityConditionalAccessPolicy -BodyParameter $Params | Out-Null
                            }


                            # Check and set the Fido2Passwordless conditional access policy
                            # Handy command to list all active settings
                            # Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq "Fido2Passwordless" } | ConvertTo-Json -Depth 100

                            # Define the name of the conditional access policy
                            $displayName = "Fido2Passwordless"

                            # Retrieve the conditional access policy that has the name defined above.
                            $conditionalAccessPolicy = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.DisplayName -eq $displayName }

                            # Prepare the parameters for the conditional access policy
                            $Params = @{
                                DisplayName = $displayName
                                State = "enabled"
                                Conditions = @{
                                    Applications = @{
                                        IncludeApplications = @("All")
                                    }
                                    ClientAppTypes = @("all")       
                                    Users = @{
                                        IncludeGroups = @($Group3.id)
                                    }
                                }
                                GrantControls = @{
                                    Operator = "OR"
                                    BuiltInControls = @()
                                    AuthenticationStrength = @{
                                        Id = $FIDO2PasswordlessID
                                        PolicyType = "custom"
                                        RequirementsSatisfied = "mfa"
                                    }
                                }
                                SessionControls = @{
                                     SignInFrequency = @{
                                        AuthenticationType =  "primaryAndSecondaryAuthentication"
                                        FrequencyInterval =  "timeBased"
                                        IsEnabled =  $true
                                        Type = "days"
                                        Value = "1"
                                    }
                                 }
                            }

                            # If the conditional access policy already exists, delete it then recreate it (too risky to update the parameters!)
                            if ($conditionalAccessPolicy) {
                                Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $conditionalAccessPolicy.Id
                                New-MgIdentityConditionalAccessPolicy -BodyParameter $Params | Out-Null
                            # Otherwise, create a new conditional access policy
                            } else {
                                New-MgIdentityConditionalAccessPolicy -BodyParameter $Params | Out-Null
                            }


                            Write-Host "`n`n[MfaPasslessPizazz AutoConf Completed]`n" -ForegroundColor Green
                            Pause 

                       } else { Write-Host "Operation cancelled."}
                                                      
                            } # *** END AutoConf Script ***

       
                  default { # *** Default ***
                            Write-Host "Oopsie! Incorrect choice. Dive into the sea of available options and give it another go!"
                            Start-Sleep -Seconds 1
                          } # *** End Default ***

                    }

} while ($true)