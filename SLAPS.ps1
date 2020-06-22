function main
{
    # Create file to hold script
    $scriptfolder = "C:\ProgramData\MyCompany\CorpIT\"
    $scriptname = "SLAPS.ps1"
    "Checking if $scriptfolder folder exists..."
    if(!(test-path ($scriptfolder -replace '\\CorpIT\\')))
    {
        "Creating $($scriptfolder -replace '\\CorpIT\\')"
        mkdir ($scriptfolder -replace '\\CorpIT\\')
    }
    if(!(test-path $scriptfolder))
    {
        "Creating $scriptfolder"
        mkdir $scriptfolder
    }
    
    # Start log file
    Start-Transcript -Path "$($scriptfolder)SLAPS-wrapper.log"

    if(!(test-path "$scriptfolder$scriptname"))
    {
        "Script file doesn't exist. Creating $scriptfolder$scriptname"
        "" | out-file "$scriptfolder$scriptname"
    }

    # Set permissions on file - no inheritence, fullaccess for system, no other ACLs
    "Locking down permissions on script file..."
    $acl = get-acl "$scriptfolder$scriptname"
    $ar = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","Allow")
    $acl.AddAccessRule($ar)
    $acl.SetAccessRuleProtection($true,$false)
    $acl | set-acl "$scriptfolder$scriptname"

    # Write script content to file
    "Writing script content to $scriptfolder$scriptname"
    $content = Get-ScriptContent
    $content | out-file "$scriptfolder$scriptname"

    # Check if scheduled task exists
    "Checking if scheduled task exists..."
    if(!(Get-ScheduledTask "SLAPS"))
    {
        # If not, create scheduled task
        $time = New-ScheduledTaskTrigger -Daily -DaysInterval 14 -At 3am
        $user = "SYSTEM"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ex bypass -file `"$scriptfolder$scriptname`""
        $settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName "SLAPS" -Trigger $Time -User $User -Action $Action -Settings $settings -RunLevel Highest -Force
    }
    
    "Running scheduled task..."
    Start-ScheduledTask "SLAPS"
    
    Stop-Transcript
}

function Get-ScriptContent
{
    return @'
    $exitCode = 0

    if(-not [System.Environment]::Is64BitProcess)
    {
        # start new PowerShell as x64 bit process, wait for it and gather exit code and standard error output
        $sysNativePowerShell = "$($PSHOME.ToLower().Replace("syswow64", "sysnative"))\powershell.exe"

        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = $sysNativePowerShell
        $processStartInfo.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
        $processStartInfo.RedirectStandardError = $true
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.CreateNoWindow = $true
        $processStartInfo.UseShellExecute = $false

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processStartInfo
        $process.Start()

        $exitCode = $process.ExitCode

        $standardError = $process.StandardError.ReadToEnd()
        if ($standardError) {
            Write-Error -Message $standardError 
        }
    }
    else
    {
       # start logging to TEMP in file "scriptname.log"
        $null = Start-Transcript -Path "C:\ProgramData\MyCompany\CorpIT\SLAPS.log"
        
        # Define the username for the Local Administrator
        $userName = "administrator"

        # Azure Function Uri (containing "azurewebsites.net") for storing Local Administrator secret in Azure Key Vault
        $uri = 'https://myfunctions.azurewebsites.net/api/Set-KeyVaultSecret?code=s0mer4nd0mstr1ng/pIZPg=='

        # Hide the $uri (containing "azurewebsites.net") from logs to prevent manipulation of Azure Key Vault
        $intuneManagementExtensionLogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
        Set-Content -Path $intuneManagementExtensionLogPath -Value (Get-Content -Path $intuneManagementExtensionLogPath | Select-String -Pattern "azurewebsites.net" -notmatch)

        "Device domain join info:"
        $joininfo = Get-WmiObject -Class Win32_ComputerSystem
        $joininfo | fl
        if($joininfo.Domain -ne 'WORKGROUP')
        {
            throw "Computer is joined to a domain! Cannot run script!"
        }
    
        $installedsoftware = Get-WmiObject -Class Win32_Product
        if($installedsoftware.name -contains 'Local Administrator Password Solution')
        {
            throw "LAPS is installed on this machine! SLAPS cannot coexist with LAPS! Exiting!"
        }
        
        $AzureADDeviceDeviceID = (Get-ChildItem -Path "hklm:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\" | select pschildname).PSChildName

        if(!$AzureADDeviceDeviceID)
        {
            "WARNING: Azure AD Device ID could not be obtained from the registry! This computer may not be Azure AD Joined!"
        }

        # Azure Function Request Body. Azure Function will strip the keyName and add a secret value. https://docs.microsoft.com/en-us/rest/api/keyvault/setsecret/setsecret
        $body = @"
        {
            "keyName": "$env:COMPUTERNAME",
            "contentType": "Local Administrator Credentials",
            "tags": {
                "Username": "$userName",
                "DeviceID": "$AzureADDeviceDeviceID"
            }
        }
"@
        
        function Upload-AzureStorage
        {
            param(
                $log
            )
            
            $sastoken = '?sv=XXXXXXXXXXXXXXXXXXX'
            $container = 'https://XXXXXXXXXXXXXX.blob.core.windows.net/slapslogs'
            
            Invoke-RestMethod `
                -URI "$container/SLAPS-$(hostname)-$([datetime]::Now.ToString('yyyy-MM-dd')).txt$sastoken" `
                -Method PUT `
                -Headers @{
                    'Content-Length' = $log.Length
                    'x-ms-blob-type' = 'BlockBlob'
                } `
                -Body $log `
                -UseBasicParsing
        }
        
        # Trigger Azure Function.
        try
        {
            "Requesting new password from Azure function..."
            $password = Invoke-RestMethod -Uri $uri -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop
        }
        catch
        {
            Write-Error "Failed to submit Local Administrator configuration. StatusCode: $($_.Exception.Response.StatusCode.value__). StatusDescription: $($_.Exception.Response.StatusDescription)"
        }

        # Convert password to Secure String
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

        # Create a new Local User, change the password if it already exists.
        try
        {
            New-LocalUser -Name $userName -Password $securePassword -PasswordNeverExpires:$true -AccountNeverExpires:$true -ErrorAction Stop
        }
        catch
        {
            # If it already exists, catch it and continue.
            if ($_.CategoryInfo.Reason -eq 'UserExistsException')
            {
                Write-Output "Local Admin '$userName' already exists. Changing password."
                $userExists = $true
            }
            else
            {
                $exitCode = -1
                Write-Error $_
            }
        }

        if ($userExists)
        {
            # Change the password of the Local Administrator
            try
            {
                Set-LocalUser -Name $userName -Password $securePassword -PasswordNeverExpires $true
            }
            catch
            {
                $exitCode = -1
                Write-Error $_
            }
        } 
        else
        {
            # Add the new Local User to the Local Administrators group
            try
            {
                Add-LocalGroupMember -Group "Administrators" -Member $userName
                Write-Output "Added Local User '$userName' to Local Administrators Group"
            }
            catch
            {
                $exitCode = -1
                Write-Error $_
            }
        }

        Get-LocalUser -Name $userName | Enable-LocalUser

        $null = Stop-Transcript
    }

    exit $exitCode
'@
}


main
