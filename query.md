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
  index="main" sourcetype="WinEventLog:Sysmon" EventCode=10 SourceImage="C:\\Windows\\System32\\rundll32.exe"
  | table _time, host, SourceImage, TargetImage, GrantedAccess, CallTrace
  | sort - _time
  ```
