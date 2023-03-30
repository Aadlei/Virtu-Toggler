using System.Management.Automation;

using var ps = PowerShell.Create();

ps.AddScript("(Get-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\")").Invoke();