# LSARights
PowerShell script to manage [LSA](https://msdn.microsoft.com/en-us/library/windows/desktop/bb545671(v=vs.85).aspx) rights.

Most parts of the script are copied from [www.pinvoke.net](http://www.pinvoke.net/default.aspx/advapi32.LsaAddAccountRights) ... I'm just the orchestrator who made it runnable as PowerShell...


# Example:
Just run the script to register the functions...

```Get-Rights user01``` to get the assigned LSA rights for user01

```Set-Right -User 'domain\user02' -Right 'SeServiceLogonRight'``` to assign LogonAsService right to user02

```Remove-Right -Right 'SeServiceLogonRight'``` to remove LogonAsService right on the current user

