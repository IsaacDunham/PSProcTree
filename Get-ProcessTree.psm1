function Format-PSTree {
  [CmdletBinding()]
  param (
    [Parameter(ValueFromPipeline, Mandatory)]
    [psobject] $process,
    [string]$processName = 'Image',
    [string]$commandLine = 'CommandLine',
    [string]$guidProperty = 'Key',
    [string]$parentGuidProperty = 'ParentKey',
    [switch]$truncate
  )

  begin {
    $processesBuffer = [System.Collections.Generic.List[object]]::new()
  }
  process {
    $processesBuffer.Add($process)
  }

  end {
    $processes = $processesBuffer

  # Index nodes by Key
  $nodesByKey = @{}
  foreach ($currentProcess in $processes) {
    $processKeyValue = $currentProcess.$guidProperty
    if ($null -ne $processKeyValue -and $processKeyValue.ToString() -ne '') {
      $nodesByKey[$processKeyValue.ToString()] = $currentProcess
    }
  }

  # children = @{parent1: [childproc1, childproc2]}
  $childrenByParentKey = @{}
  foreach ($currentProcess in $processes) {
    $parentKeyValue = $currentProcess.$parentGuidProperty
    $parentKey = if ($null -eq $parentKeyValue -or $parentKeyValue.ToString() -eq '') { '' } else { $parentKeyValue.ToString() }
    if (-not $childrenByParentKey.ContainsKey($parentKey)) { $childrenByParentKey[$parentKey] = [System.Collections.Generic.List[object]]::new() }
    $childrenByParentKey[$parentKey].Add($currentProcess)
  }

  $sortBy = @('SystemTime', 'Image')

    function Get-Children([string]$parentKey) {
        if (-not $childrenByParentKey.ContainsKey($parentKey)) { return @() }
        $childProcesses = $childrenByParentKey[$parentKey]
        return $childProcesses | Sort-Object -Property $sortBy
    }

    # rootitems = every process without a parent process found in our parsed processes
    $rootItems = @(
      foreach ($currentProcess in $processes) {
        $rootParentKeyValue = $currentProcess.$parentGuidProperty
        $rootParentKeyString = if ($null -eq $rootParentKeyValue) { '' } else { $rootParentKeyValue.ToString() }
        if ($rootParentKeyString -eq '' -or -not $nodesByKey.ContainsKey($rootParentKeyString)) { $currentProcess }
      }
     ) | Sort-Object -Property $sortBy

    $printedKeys = [System.Collections.Generic.HashSet[string]]::new()

    function Walk([object]$node, [int]$depth) {
      $nodeKey = $node.$guidProperty

      $prefix = '*' * $depth
      $syntheticMarker = if ($node.IsSynthetic) { '[SYN] ' } else { '' }

      if ($null -ne $node.$commandLine) {
        $commandLineText = $node.$commandLine
      }
      else {
        $commandLineText = "Command line unavailable (expected for EID 4688)"
      }

      $maxLength = [Math]::Max(1, [Console]::WindowWidth - 1)
      $output = "$prefix$syntheticMarker$($node.$processName) (PID $($node.ProcessId), PPID $($node.ParentProcessId)) - $commandLineText"

      if ($truncate) {
        if ($output.Length -gt $maxLength) {
          $output = $output.Substring(0, $maxLength)
        }
      }
      $output


      # if key is already present, skip
      if ($nodeKey -ne '' -and -not $printedKeys.Add($nodeKey)) { return }

      foreach ($childProcess in Get-Children $nodeKey) {
        Walk $childProcess ($depth + 1)
      }

    }

    foreach ($rootProcess in $rootItems) {
      Walk $rootProcess 0
    }
  }
}

function Get-Processes {
  [CmdletBinding()]
  param (
    [string]$Path,
    [string]$LogName,
    [Parameter(Mandatory)][ValidateSet('Sysmon','Security')][string]$LogType
  )

  if ([string]::IsNullOrEmpty($Path) -and [string]::IsNullOrEmpty($LogName)) {
    Write-Error "Please specify either a Path or LogName."
    return
  }

  if (-not [string]::IsNullOrEmpty($Path) -and -not [string]::IsNullOrEmpty($LogName)) {
    Write-Error "Please specify only a Path or a LogName, not both."
    return
  }

  # Set XPath based on LogType
  if ($LogType -eq "Sysmon") {
    $xPath = '*[System[(EventID=1)]]'
  }
  elseif ($LogType -eq "Security") {
    $xPath = '*[System[(EventID=4688)]]'
  }

  # Read events and normalize to common schema
  $normalizedProcesses = @()
  
  if ($Path) {
    $events = Get-WinEvent -Path $Path -FilterXPath $xPath -ErrorAction Stop
  } else {
    $events = Get-WinEvent -LogName $LogName -FilterXPath $xPath -ErrorAction Stop
  }

  # $event = an automatic variable used by powershell
  foreach ($eventRecord in $events) {
    $eventXml = [xml]$eventRecord.ToXml()
    
    $systemTime = $eventXml.Event.System.TimeCreated.SystemTime
    
    $eventData = @{}
    foreach ($dataNode in $eventXml.Event.EventData.Data) {
      $eventData[$dataNode.Name] = $dataNode.'#text'
    }
    
    # Normalize based on LogType
    if ($LogType -eq "Sysmon") {
      $normalized = [PSCustomObject]@{
        EventSource = 'Sysmon'
        SystemTime = $systemTime
        Key = $eventData['ProcessGuid']
        ParentKey = $eventData['ParentProcessGuid']
        ProcessId = $eventData['ProcessId']
        ParentProcessId = $eventData['ParentProcessId']
        Image = $eventData['Image']
        CommandLine = $eventData['CommandLine']
        ParentImage = $eventData['ParentImage']
        ParentCommandLine = $eventData['ParentCommandLine']
        IsSynthetic = $false
      }
    }
    # EID 4688
    elseif ($LogType -eq "Security") {
      $newProcessId = [Convert]::ToInt32($eventData['NewProcessId'], 16)
      $parentProcessId = [Convert]::ToInt32($eventData['ProcessId'], 16)
      
      # For 4688, since no guid, we attempt to identify each process uniquely via Key: NewProcessId + NewProcessName.
      # unfortunately, without a parent timestamp, no way to avoid inaccuracies from eventual pid reuse. 
      
      $normalized = [PSCustomObject]@{
        EventSource = 'Security'
        SystemTime = $systemTime
        Key = "$newProcessId|$($eventData['NewProcessName'])"
        ParentKey = "$parentProcessId|$($eventData['ParentProcessName'])"
        ProcessId = $newProcessId
        ParentProcessId = $parentProcessId
        Image = $eventData['NewProcessName']
        CommandLine = $eventData['CommandLine']
        ParentImage = $eventData['ParentProcessName']
        ParentCommandLine = $null
        IsSynthetic = $false
      }
    }
    
    $normalizedProcesses += $normalized
  }

  # use parent properties to create synthetic process tree roots
  $processesByKey = @{}
  foreach ($currentProcess in $normalizedProcesses) {
    if ($currentProcess.Key) {
      $processesByKey[$currentProcess.Key] = $currentProcess
    }
  }
  
  $syntheticParents = @{}
  foreach ($currentProcess in $normalizedProcesses) {
    $needsSyntheticParent = $false
    
    if ($currentProcess.ParentKey -and -not $processesByKey.ContainsKey($currentProcess.ParentKey)) {
      # parent exists but is not in our list of processes
      $needsSyntheticParent = $true
      $syntheticKey = $currentProcess.ParentKey
    }
    elseif (-not $currentProcess.ParentKey -and $currentProcess.ParentProcessId) {
      $needsSyntheticParent = $true
      $syntheticKey = "SYNTH-PID:$($currentProcess.ParentProcessId)-IMG:$($currentProcess.ParentImage)"
      $currentProcess.ParentKey = $syntheticKey
    }
    
    if ($needsSyntheticParent -and -not $syntheticParents.ContainsKey($syntheticKey)) {
      $synthetic = [PSCustomObject]@{
        EventSource = $currentProcess.EventSource
        SystemTime = $null
        Key = $syntheticKey
        ParentKey = $null
        ProcessId = $currentProcess.ParentProcessId
        ParentProcessId = $null
        Image = $currentProcess.ParentImage
        CommandLine = $currentProcess.ParentCommandLine
        ParentImage = $null
        ParentCommandLine = $null
        IsSynthetic = $true
      }
      $syntheticParents[$syntheticKey] = $synthetic
    }
  }
  
  # combine synth parents with normal process list
  $normalizedProcesses += $syntheticParents.Values

  return $normalizedProcesses
}

function Get-ProcessTree {
  [CmdletBinding(DefaultParameterSetName='File')]
  param (
    [Parameter(ParameterSetName='File')]
    [string]$Path,
    
    [Parameter(ParameterSetName='Live')]
    [ValidateSet('Security', 'Sysmon', 'Microsoft-Windows-Sysmon/Operational')]
    [string]$LogName,
    
    [ValidateSet('Sysmon', 'Security')]
    [string]$LogType,

    [switch]$Truncate,
    [Switch]$Help
  )

  if ($Help) {
    Write-Host @"
Get-ProcessTree - Build and display process trees from Windows event logs

DESCRIPTION:
  Reads process creation logs (Sysmon EID 1 or Security EID 4688) and displays
  them as a hierarchical tree showing parent-child relationships. Missing parent
  processes are filled in with synthetic parents identifiable via [SYN].

  Note: Process trees derived from event ID 4688 will eventually run into
  inaccuracies (collisions) due to telemetry limitations + PID reuse.

PARAMETERS:
  -Path <string>          Path to .evtx file
  -LogName <string>       Name of event log (e.g., 'Microsoft-Windows-Sysmon/Operational')
  -LogType <string>       'Sysmon' or 'Security' (required)
  -Truncate               Limits per-process display output to width of terminal (useful for reading long command lines at a glance)
  -Help                   Show this help

EXAMPLES:
  # Read from evtx file
  Get-ProcessTree -Path .\sysmon.evtx -LogType Sysmon

  # Read from live event log
  Get-ProcessTree -LogName 'Microsoft-Windows-Sysmon/Operational' -LogType Sysmon
"@
    return
  }

  if ($LogName -eq "Sysmon" -or $LogName -eq "Microsoft-Windows-Sysmon/Operational") {
    $LogName = "Microsoft-Windows-Sysmon/Operational"
    $LogType = "Sysmon"
  }
  elseif ($LogName -eq "Security") {
    $LogType = "Security"
  }

  $getProcessesParams = @{
    LogType = $LogType
  }
  
  if ($PSCmdlet.ParameterSetName -eq 'File') {
    $getProcessesParams['Path'] = $Path
  } else {
    $getProcessesParams['LogName'] = $LogName
  }

  Get-Processes @getProcessesParams | Format-PSTree -Truncate:$Truncate
}
