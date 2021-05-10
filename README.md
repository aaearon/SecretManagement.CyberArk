# SecretManagement.CyberArk
A [SecretManagement](https://github.com/powershell/secretmanagement) extension for [CyberArk](https://www.cyberark.com/). The [psPAS](https://github.com/pspete/psPAS) module is used to communicate with the Vault.

## Prerequisities
* The [psPAS](https://github.com/pspete/psPAS) Powershell module
* The [SecretManagement](https://github.com/powershell/secretmanagement) Powershell module

## Installation
From PowerShell Gallery

`Install-Module SecretManagement.CyberArk`

## Registration
Once installed, it must be registered as an extension for `SecretManagement`.

`Register-SecretVault -ModuleName SecretManagement.CyberArk`

## Usage
You use the typical `SecretManagement` commands such as `Get-Secret` and `Set-Secret`.

### Examples
To retrieve the password for an account named `localAdmin01`:

`Get-PASAccount -search localAdmin01 -safeName Windows | Get-Secret`

or

`Get-Secret -Name localAdmin01`

Note: If multiple results are returned from CyberArk the first one is provided.

To retrieve the password for an account named `linuxAdmin01` where policy requires a reason:

`Get-Secret -Name localAdmin01 -AdditionalParameters @{Reason="To do things"}`

To create a new credential in the Vault use:

```
$Secret = ConvertTo-SecureString "verySecret!" -AsPlainText -Force

$NewCredentialProperties = @{
    address="iosharp.lab";
    userName="localAdmin10";
    platformId="WindowsDomainAccount";
    safeName="Windows"}

Set-Secret -Secret $Secret -AdditionalParameters $NewCredentialProperties
```

Note: The value passed to the `Name` argument will be used as the `name` property for the account in CyberArk. If you want CyberArk to generate the name for the account automatically, do not use the `Name` argument.