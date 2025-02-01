- List all the sourcetypes available
```
index="main" | stats count by sourcetype&
```
- List event code
```
index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode
```
