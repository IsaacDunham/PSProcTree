# About
This is a PowerShell script that creates simple, basic process trees from Windows Security Event log 4688 or from Sysmon
log 1. 

To use this tool, simply import the `.psm1` module and then run the `Get-ProcessTree` cmdlet.

# Examples:
``` powershell title:"Import Module"
Import-Module Get-ProcessTree.psm1
```

``` powershell title:"Show help dialogue"
Get-ProcessTree -Help
```

``` PowerShell title:"Show process tree from live Sysmon logs"
Get-ProcessTree -LogName Sysmon
```

``` PowerShell title:"Show process tree for logs at a file path"
Get-ProcessTree -Path "C:\Sysmon.evtx" -LogType Sysmon
```
