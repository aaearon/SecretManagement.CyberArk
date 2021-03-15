# SecretManagement.CyberArk
A [SecretManagement](https://github.com/powershell/secretmanagement) extension for [CyberArk](https://www.cyberark.com/). The [psPAS](https://github.com/pspete/psPAS) module is used to communicate with the Vault.

## Prerequisities
* The [psPAS](https://github.com/pspete/psPAS) Powershell module
* The [SecretManagement](https://github.com/powershell/secretmanagement) Powershell module

## Installation
It is not yet available in the PowerShell Gallery as I want it to be a bit more mature so as of now it needs to be installed by hand.

## Registration
Once installed, it must be registered as an extension for `SecretManagement`.

`Register-SecretVault -ModuleName SecretManagement.CyberArk`

## Usage
You use the typical `SecretManagement` commands such as `Get-Secret` and `Set-Secret`.

### Examples
To retrieve the password for an account named `localAdmin01`:

`Get-Secret -Name localAdmin01`

Note: If multiple results are returned from CyberArk the first one is provided.

To retrieve the password for an account named `linuxAdmin01` where policy requires a reason:

`Get-Secret -Name localAdmin01 -AdditionalProperties @{Reason="To do things"}`

To create a new credential in the Vault use:

```
$Secret = ConvertTo-SecureString "verySecret!" -AsPlainText -Force

$NewCredentialProperties = @{
    address="iosharp.lab"; 
    userName="localAdmin10"; 
    platformId="WindowsDomainAccount"; 
    safeName="Windows"} 

Set-Secret -Secret $Secret -AdditionalProperties $NewCredentialProperties
```

Note: The `Name` argument should not be used. If you want to explicitly define the name of the new credential you are adding to CyberArk then define `name` as a key inside the Hashtable passed as `AdditionalProperties`.