### List all the sourcetypes available
 ```
 index="main" | stats count by sourcetype
 ```
### List event code
 ```
 index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode
 ```
### Unusual Parent/Process ([Hunt Evil Cheat Sheet](https://sansorg.egnyte.com/dl/WFdH1hHnQI))
  ```
  index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | stats count by ParentImage, Image
  ```
  * More focus on CMD and Powershell
   ```
   index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") | stats count by ParentImage, Image
   ```
   * Check cmd with the suspicious parent Image :
     ```
     index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") AND ParentImage="*rundll*" | stats count by ParentImage,ParentProcessId, Image, CommandLine
     ```
  ### Detect potential DCsync:
 ```
 index="main" EventCode=4662 Access_Mask=0x100 Account_Name!=*$
 ```
Event Code 4662 is triggered when an Active Directory (AD) object is accessed. Access Mask 0x100 specifically requests Control Access typically needed for DCSync's high-level permissions. 
Check for the GUID [DS-Replication-Get-Changes-All extended right](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all) (**1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
**).

### Detect Process interact with lsass
 ```
 index="main" EventCode=10 lsass | stats count by SourceImage
 
 ```
  One find suspicious interaction check what it's has been done
 ```
 index="main" EventCode=10 lsass SourceImage="C:\\Windows\\System32\\notepad.exe"
 ```
### Alerts from malicious malware based on API calls from UNKNOWN regions of memory
 ```
 index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* SourceImage!="C:\\Windows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage, TargetImage, CallTrace
 ```

### Detecting Unmanaged PowerShell/C-Sharp Injection with event 7
  ```
  index="main" sourcetype="WinEventLog:Sysmon" host="XXXX"  EventCode=7  ImageLoaded="*clrjit.dll*" OR  ImageLoaded="*clr.dll*" 
  | stats count by Image
  ```
  Found a suspicious process and check what it does:
  ```
  index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 ParentImage="C:\\Windows\\System32\\rundll32.exe"
  | table _time, Hostname, ParentImage, Image, CommandLine, ParentProcessName
  | sort - _time```
  ```
  ```
  index="main" sourcetype="WinEventLog:Sysmon" EventCode=10 SourceImage="C:\\Windows\\System32\\rundll32.exe"
  | table _time, host, SourceImage, TargetImage, GrantedAccess, CallTrace
  | sort - _time
  ```
### [Detecting](https://hurricanelabs.com/splunk-tutorials/splunking-with-sysmon-part-3-detecting-psexec-in-your-environment/) [PSexec](https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution) :  
As mentionnend on the [Detecting](https://hurricanelabs.com/splunk-tutorials/splunking-with-sysmon-part-3-detecting-psexec-in-your-environment/) psexec follow some "timeline" during his ececution 
 - *Case 1: Leveraging Sysmon Event ID 13*
    ```
    index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath" | rex field=Details "(?<reg_file_name>[^\\\]+)$" | eval reg_file_name     = lower(reg_file_name), file_name = if(isnull(file_name),reg_file_name,lower(file_name)) | stats values(Image) AS Image, values(Details) AS RegistryDetails, values(_time) AS EventTimes, count by file_name, ComputerName
    ```
    try to fucs on the less frequent 
>>Case 2: Leveraging Sysmon Event ID 11
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System | stats count by TargetFilename

```

>> Case 3: Leveraging Sysmon Event ID 18

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System | stats count by PipeName

```
### Example: Detection Of Misspelling Legitimate Binaries for example psexec

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (CommandLine="*psexe*.exe" NOT (CommandLine="*PSEXESVC.exe" OR CommandLine="*PsExec64.exe")) OR (ParentCommandLine="*psexe*.exe" NOT (ParentCommandLine="*PSEXESVC.exe" OR ParentCommandLine="*PsExec64.exe")) OR (ParentImage="*psexe*.exe" NOT (ParentImage="*PSEXESVC.exe" OR ParentImage="*PsExec64.exe")) OR (Image="*psexe*.exe" NOT (Image="*PSEXESVC.exe" OR Image="*PsExec64.exe")) |  table Image, CommandLine, ParentImage, ParentCommandLine

```


### Example: Detection Of Utilizing Archive Files For Transferring Tools Or Data Exfiltration by detecting creation of archive

```
index="main" EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z") | stats count by ComputerName, User, TargetFilename | sort - count

```
### Example: Detection Of Utilizing PowerShell or MS Edge For Downloading Payloads/Tools
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*powershell.exe*" |  stats count by Image, TargetFilename |  sort + count

```
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*msedge.exe" TargetFilename=*"Zone.Identifier" |  stats count by TargetFilename |  sort + count

```
*Zone.Identifier is indicative of a file downloaded from the interne

### Example: Detection Of Execution From Atypical Or Suspicious Locations

```
index="main" EventCode=1 | regex Image="C:\\\\Users\\\\.*\\\\Downloads\\\\.*" |  stats count by Image
```
check less frequent
###  Example: Detection Of Executables or DLLs Being Created Outside The Windows Directory
```
index="main" EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll") TargetFilename!="*\\windows\\*" | stats count by User, TargetFilename | sort + count
```
Check less frequent first

###  Detection Of Using Non-standard Ports For Communications/Transfers
```
index="main" EventCode=3 NOT (DestinationPort=80 OR DestinationPort=443 OR DestinationPort=22 OR DestinationPort=21) | stats count by SourceIp, DestinationIp, DestinationPort | sort - count

```
## Behavior With Splunk Based On Analytics

###monitoring the number of network connections initiated by a process within a certain time frame
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | bin _time span=1h | stats count as NetworkConnections by _time, Image | streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image | eval isOutlier=if(NetworkConnections > (avg + (0.5*stdev)), 1, 0) | search isOutlier=1
```
The eval command is then used to create a new field, isOutlier, and assigns it a value of 1 for any event where the number of network connections is more than 0.5 standard deviations away from the average. This labels these events as statistically anomalous and potentially indicative of suspicious activity.
### Detection Of Abnormally Long Commands
```
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe | eval len=len(CommandLine) | table User, len, CommandLine | sort - len
```
Could be noisy so need to filtered for example
```
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe ParentImage!="*msiexec.exe" ParentImage!="*explorer.exe" | eval len=len(CommandLine) | table User, len, CommandLine | sort - len
```
### Detection Of Abnormal cmd.exe Activity
```
index="main" EventCode=1 (CommandLine="*cmd.exe*") | bucket _time span=1h | stats count as cmdCount by _time User CommandLine | eventstats avg(cmdCount) as avg stdev(cmdCount) as stdev | eval isOutlier=if(cmdCount > avg+1.5*stdev, 1, 0) | search isOutlier=1
```
The following search identifies unusual cmd.exe activity within a certain time range. It uses the bucket command to group events by hour, calculates the count, average, and standard deviation of cmd.exe executions, and flags outliers.


### Detection Of Processes Loading A High Number Of DLLs In A Specific Time
```
index="main" EventCode=7 | bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded

```
COuld be noisy this is an example of filtering request: 
```
index="main" EventCode=7 NOT (Image="C:\\Windows\\System32*") NOT (Image="C:\\Program Files (x86)*") NOT (Image="C:\\Program Files*") NOT (Image="C:\\ProgramData*") NOT (Image="C:\\Users\\waldo\\AppData*")| bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded | sort - unique_dlls_loaded
```
### Detection Of Transactions Where The Same Process Has Been Created More Than Once On The Same Computer
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | transaction ComputerName, Image | where mvcount(ProcessGuid) > 1 | stats count by Image, ParentImage
```
We can filter per most event and try to identify Pprocess and Process supect relation. For example: 
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1  | transaction ComputerName, Image  | where mvcount(ProcessGuid) > 1 | search Image="C:\\Windows\\System32\\rundll32.exe" ParentImage="C:\\Windows\\System32\\svchost.exe" | table CommandLine, ParentCommandLine
```
### source process images that are creating an unusually high number of threads in other processes
```
index=* sourcetype="WinEventLog:Sysmon" EventCode=8 | bin _time span=1h | stats count as TargetImage by _time, SourceImage | streamstats avg(TargetImage) as avg stdev(TargetImage) as stdev by Image
| sort -TargetImage
```
