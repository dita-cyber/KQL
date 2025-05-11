# KQL

General search<br/>

search "ENTITY"<br/>
| summarize count() by $table <br/>

---

Logins<br/>

SigninLogs<br/>
| where TimeGenerated > ago(30d)<br/>
| where * contains "email_account"<br/>
| project TimeGenerated, UserPrincipalName, UserDisplayName, Location, LocationDetails, IPAddress, Status, ConditionalAccessStatus, AuthenticationRequirement, AuthenticationDetails, ResultType, ResultDescription, UserAgent, MfaDetail, AppDisplayName, DeviceDetail<br/>
| sort by TimeGenerated <br/>

---

Password Changes<br/>

AuditLogs<br/>
| where TimeGenerated >= ago(15d)<br/>
| where OperationName == "Change user password"<br/>
| where TargetResources[0].userPrincipalName == "email_account" <br/>

---

OfficeActivity<br/>

OfficeActivity <br/>
| search "entity" or "entity" <br/>
| where Operation == "operation_here"<br/>

---

AlertEvidence<br/>

AlertEvidence<br/>
| where * contains 'entity"<br/>

---

Emails and Attachments<br/>

EmailEvents<br/>
| search "entity"<br/>

EmailAttachmentInfo<br/>
| where * contains "entity"<br/>

EmailEvents <br/>
| where TimeGenerated >= ago(3d) and EmailDirection !~ 'Inbound' and SenderFromDomain =~ 'domain.com' <br/>
| summarize event_count = count() by bin(TimeGenerated, 1h), SenderFromAddress | sort by TimeGenerated, SenderFromAddress <br/>

---

Device Events<br/>

DeviceEvents<br/>
| where DeviceName contains "entity"<br/>

DeviceNetworkEvents<br/>
| where DeviceName contains "entity"<br/>
| where InitiatingProcessFileName contains "powershell"<br/>
| where ActionType !contains "ConnectionFailed"<br/>
| where InitiatingProcessAccountName contains "entity"<br/>
| summarize count() by RemotePort<br/>

DeviceNetworkEvents<br/>
| where DeviceName contains "entity"<br/>
| where InitiatingProcessFileName contains "powershell"<br/>
| where ActionType contains "ConnectionFailed"<br/>
| where InitiatingProcessAccountName contains "entity"<br/>
| where RemotePort == 3389<br/>
| summarize count() by RemoteIP, RemoteUrl<br/>
| distinct RemoteIP <br/>

---

Common Security Logs are a collection of events formatted in the Common Event Format (CEF), typically received from security devices like firewalls from vendors such as Cisco and Palo Alto. These logs are designed to be easily readable and standardized for security information and event management (SIEM) systems, facilitating efficient analysis of security events and threats.

Syslog, on the other hand, is a widely used protocol for logging messages across various systems and network devices. It allows for the centralized collection and monitoring of system messages, including events, errors, warnings, and user activity. This standardization helps IT administrators effectively troubleshoot and manage network and system issues.

While both Syslog and CEF are popular standards for logging and event management, CEF provides a pre-parsed, structured format specifically for security-related events, such as details on source and destination IPs, ports, and protocols. Syslog messages, in contrast, may contain a broader range of system information that requires interpretation.

Common Security Logs<br/>

CommonSecurityLog<br/>
| where TimeGenerated > ago(20d)<br/>
| where DeviceVendor contains 'vendor_entity'<br/>
| where Computer contains "entity"<br/>
| summarize count() by bin(TimeGenerated, 5h)<br/>
| render columnchart <br/>

CommonSecurityLog<br/>
| where TimeGenerated > ago(5d)<br/>
| where DeviceVendor contains 'Palo Alto Networks'<br/>
| summarize arg_max(TimeGenerated, *) , count() by Computer<br/>
| project Computer, TimeGenerated<br/>
| sort by TimeGenerated asc<br/> 

Syslog<br/>

Syslog<br/>
| project TimeGenerated, Computer, HostIP<br/>
| where TimeGenerated > startofday(ago(90d))<br/>
| summarize count() by bin(TimeGenerated, 5h), Computer <br/>

Syslog <br/>
| where TimeGenerated > ago(15d) <br/>
| where Computer in ("entity", "entity", "entity") <br/>
| summarize arg_max(TimeGenerated, *) , count() by Computer <br/>
| project Computer, TimeGenerated <br/>
| sort by TimeGenerated asc  <br/>

union Syslog,CommonSecurityLog<br/>
| where TimeGenerated > ago(14d)<br/>
| summarize count() by bin(TimeGenerated, 10m), Type<br/>
| where Computer contains "entity" <br/>
| render columnchart <br/>

---

Heartbeat<br/>

Heartbeat<br/>
| where Computer contains "entity"<br/>
| where TimeGenerated > ago(20d)<br/>
| summarize count() by bin(TimeGenerated, 2h)<br/>

---

Usage Spike<br/>

Usage<br/>
| project TimeGenerated, DataType, Quantity<br/>
| where TimeGenerated > ago(90d)<br/>
| where DataType in ('CommonSecurityLog','AADNonInteractiveUserSignInLogs','SecurityEvent','Syslog','DnsEvents')<br/>
| summarize IngestionVolumeMB=sum(Quantity) by bin(TimeGenerated, 1d), DataType<br/>
| render columnchart <br/>

Usage <br/>
| where TimeGenerated > startofday(ago(1d)) <br/>
| where StartTime >= startofday(ago(1d)) <br/>
| where IsBillable == true <br/>
| summarize TotalVolumeGB = sum(Quantity) / 1000 by bin(StartTime, 1d) <br/>
| summarize Tot=make_list_if(TotalVolumeGB,StartTime==startofday(ago(1d))) <br/>
| where Tot[0]>200 //threshold.<br/>
| project-rename TotalVolumeRecievedGB=Tot<br/>

Usage
| where TimeGenerated > startofday(ago(1d))<br/>
| where StartTime >= startofday(ago(1d)) and EndTime <= startofday(now())<br/>
| where IsBillable == true<br/>
| summarize TotalVolumeGB = sum(Quantity) / 1000 <br/>







