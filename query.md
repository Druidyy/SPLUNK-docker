- List all the sourcetypes available
```
index="main" | stats count by sourcetype&
```
- List event code
```
index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode
```

- Unusual Parent/Process ( Hunt Evil Cheet sheat [Hunt Evil] (https://sansorg.egnyte.com/dl/WFdH1hHnQI)
  ```
  index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | stats count by ParentImage, Image
  ```
More focus on CMD and Powershell
  ```
  index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") | stats count by ParentImage, Image
  ```
