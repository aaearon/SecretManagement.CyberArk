﻿# Credit for most of this goes to https://github.com/JustinGrote/SecretManagement.KeePass/blob/main/SecretManagement.KeePass/Tests/Get-Secret.Tests.ps1
Describe "Get-Secret" {
    BeforeAll {
        Get-Module 'SecretManagement.CyberArk' | Remove-Module -Force
        Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

        $ExtensionModule = Import-Module "$PSScriptRoot/../SecretManagement.CyberArk.Extension/*.psd1" -Force -PassThru

        Mock Get-PASAccountPassword -MockWith {
            $Result = [PSCustomObject]@{
                Password = 'fake'
                userName = 'localAdmin01'
            }
            $Result | Add-Member -MemberType ScriptMethod -Name 'ToSecureString' -Value { $this | Select-Object -ExpandProperty Password | ConvertTo-SecureString -AsPlainText -Force }
            return $Result
        }
        Mock Get-PASAccount -MockWith {
            return [PSCustomObject]@{
                name     = 'localAdmin01'
                userName = 'localAdmin01'
                Id       = '1'
            }
        }
    }

    AfterAll {
        Remove-Module $ExtensionModule -Force
    }

    It 'should return a <PSType> for <SecretName>' {
        $Secret = Get-Secret -name $SecretName
        $Secret | Should -Not -BeNullOrEmpty
        $Secret | Should -BeOfType $PSType
    } -TestCases (
        @{SecretName = 'localAdmin01'; PSType = 'System.Management.Automation.PSCredential' }
    )

    It 'should show a warning when multiple secrets are found' {
        Mock Get-PASAccount -MockWith {
            $Results = @(
                [PSCustomObject]@{
                    name     = 'localAdmin01'
                    userName = 'localAdmin01'
                    Id       = '1'
                },
                [PSCustomObject]@{
                    name     = 'localAdmin02'
                    userName = 'localAdmin02'
                    Id       = '2'
                }
            )
            return $Results
        }
        Mock Write-Warning -MockWith {}

        Get-Secret -name 'admin'
        Should -Invoke -CommandName Write-Warning
    }

    It 'should have a PASAccount parameter' {
        'PASAccount' | Should -BeIn ((Get-Command -Module $ExtensionModule.Name -Name 'Get-Secret').Parameters.Keys)
    }
}