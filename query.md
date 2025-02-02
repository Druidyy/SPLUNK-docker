* List all the sourcetypes available
 ```
 index="main" | stats count by sourcetype
 ```
* List event code
 ```
 index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode
 ```
* Unusual Parent/Process ([Hunt Evil Cheat Sheet](https://sansorg.egnyte.com/dl/WFdH1hHnQI))
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
* Detect potential DCsync:
 ```
 index="main" EventCode=4662 Access_Mask=0x100 Account_Name!=*$
 ```
Event Code 4662 is triggered when an Active Directory (AD) object is accessed. Access Mask 0x100 specifically requests Control Access typically needed for DCSync's high-level permissions. 
Check for the GUID [DS-Replication-Get-Changes-All extended right](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all) (**1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
**).

* Detect Process interact with lsass
 ```
 index="main" EventCode=10 lsass | stats count by SourceImage
 
 ```
  One find suspicious interaction check what it's has been done
 ```
 index="main" EventCode=10 lsass SourceImage="C:\\Windows\\System32\\notepad.exe"
 ```
* Alerts from malicious malware based on API calls from UNKNOWN regions of memory
 ```
 index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* SourceImage!="C:\\Windows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage, TargetImage, CallTrace
 ```

* Detecting Unmanaged PowerShell/C-Sharp Injection with event 7
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
## [Detecting](https://hurricanelabs.com/splunk-tutorials/splunking-with-sysmon-part-3-detecting-psexec-in-your-environment/) [PSexec](https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution) :  

 - *Case 1: Leveraging Sysmon Event ID 13*
    ```
    index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath" | rex field=Details "(?<reg_file_name>[^\\\]+)$" | eval reg_file_name     = lower(reg_file_name), file_name = if(isnull(file_name),reg_file_name,lower(file_name)) | stats values(Image) AS Image, values(Details) AS RegistryDetails, values(_time) AS EventTimes, count by file_name, ComputerName
    ```
>>Case 2: Leveraging Sysmon Event ID 11
```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System | stats count by TargetFilename

```

>> Case 3: Leveraging Sysmon Event ID 18

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System | stats count by PipeName

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
