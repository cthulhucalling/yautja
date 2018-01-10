# yautja
Splunk query tool for searching for network connections initiated by Powershell and VBScript. 

This tool will query Splunk for Carbon Black data for outbound network connections attempts initiated by powershell.exe, cscript.exe, or wscript.exe. Direct outbound connection attempts are reported first. Then, the script will do a pivot query for proxy-aware connections.

If anyone actually uses this, it will obvious require a signficant amount of tweaking to run properly in your environment.
