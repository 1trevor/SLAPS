# Serverless Local Administrator Password Solution (SLAPS)

## SLAPS.ps1
Script that needs to be deployed (in SYSTEM context) to Windows 10 Clients via Intune. Creates a scheduled task that changes the local administrator password every 14 days.

## New-LocalAdmin.ps1
Script that is executed by the scheduled task.

## Set-KeyVaultSecret.ps1
Script for Azure Functions App v2

**HTTP Method:** POST

**Example Request Body:**
```json
{
    "keyName": "TEST-PC01",
    "contentType": "Local Administrator Credentials",
    "tags": {
        "Username": "administrator"
    }
}
```
