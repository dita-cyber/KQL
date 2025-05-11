# KQL

**My Go-To Microsoft Queries**

Over the last three years, I've relied on these queries to help me efficiently search, analyze, and react to all alerts and events I encountered as a SIEM technician and SOC analyst. Knowing KQL (Kusto Query Language) is a very important skill for all professionals working on Microsoft environments. 

Below I will list all KQL queries I use on my day to day; however, you can find the complete information of all tables and its use cases under the official Microsoft documentation about KQL and advanced hunting schema.

**Kusto Query Language overview:**
https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric

**KQL quick reference:**
https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference?view=microsoft-fabric

**Understand the advanced hunting schema:**
https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables

---

**General search**

The search function is my starting point for a broad exploration across all tables. It allows me to identify the presence of specific entities across the dataset and list all tables that specific term shows for the time range I have defined.

```
search "ENTITY"<br/>
| summarize count() by $table <br/>
```

---

Logins<br/>

SigninLogs table help me with tracking user login activities. It provides detailed information on login attempts, including user details and location data. This query focuses on recent activity and sorts it for easy review.

From my experience I found the most useful collumns are:

- TimeGenerated<br/>
- UserPrincipalName<br/>
- UserDisplayName<br/>
- Location<br/>
- LocationDetails<br/>
- IPAddress<br/>
- Status<br/>
- ConditionalAccessStatus<br/>
- AuthenticationRequirement<br/>
- AuthenticationDetails<br/>
- ResultType<br/>
- ResultDescription <br/>
- UserAgent<br/>
- MfaDetail<br/>
- AppDisplayName<br/>
- DeviceDetail<br/>

```
SigninLogs<br/>
| where TimeGenerated > ago(30d)<br/>
| where * contains "ENTITY"<br/>
| project TimeGenerated, UserPrincipalName, UserDisplayName, Location, LocationDetails, IPAddress, Status, ConditionalAccessStatus, AuthenticationRequirement, AuthenticationDetails, ResultType, ResultDescription, UserAgent, MfaDetail, AppDisplayName, DeviceDetail<br/>
| sort by TimeGenerated <br/>
```

---

Audit Logs<br/>

The Audit Logs table provides a detailed record of changes within Azure Active Directory (Azure AD), capturing activities such as user creation, group additions, and modifications across the Azure AD environment. It also includes entries from Azure AD Privileged Identity Management. This table helps verifyind user account compromise investigations, validating password changes, tracking new devices added to MFA, monitoring password resets, and checking when accounts are disabled or enabled. By cross-referencing this data with other sources, I gain deeper insights and enhance correlation for a more comprehensive understanding of security events accross an environment. 

```
AuditLogs<br/>
| where TimeGenerated >= ago(15d)<br/>
| where OperationName == "Change user password"<br/>
| where TargetResources[0].userPrincipalName == "ENTITY" <br/>
```

---

OfficeActivity<br/>

The OfficeActivity table is the central repository for all Office 365-related events, capturing logs from applications like Microsoft Exchange 365, Microsoft SharePoint 365, and OneDrive. It includes both operational and audit events, making it a rich source of information for monitoring user activity. I leverage this table to investigate scenarios such as high download volumes, which might indicate potential data exfiltration or extensive OneDrive sync events. The detailed logs allow me to examine the user agent, file extensions, and file paths.

```
OfficeActivity <br/>
| search "ENTITY" or "ENTITY" <br/>
| where Operation == "operation_here"<br/>
```

---

AlertEvidence<br/>

The AlertEvidence table, part of the advanced hunting schema, provides information about various entities, such as files, IP addresses, URLs, users, and file hashed to alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Cloud Apps, and Microsoft Defender for Identity. This table is an excellent resource for constructing queries that extract detailed information on security alerts. I usually use it to verify whether a file hash has been successfully blocked, as indicated by the "remediated status: prevented" field, along with the associated timestamp.

```
AlertEvidence<br/>
| where * contains "ENTITY"<br/>
```

---

Emails and Attachments<br/>

```
EmailEvents<br/>
| search "ENTITY"<br/>
```
```
EmailAttachmentInfo<br/>
| where * contains "ENTITY"<br/>
```
```
EmailEvents <br/>
| where TimeGenerated >= ago(3d) and EmailDirection !~ 'Inbound' and SenderFromDomain =~ "DOMAIN" <br/>
| summarize event_count = count() by bin(TimeGenerated, 1h), SenderFromAddress | sort by TimeGenerated, SenderFromAddress <br/>
```
---

Device Events<br/>

```
DeviceEvents<br/>
| where DeviceName contains "ENTITY"<br/>
```
```
DeviceNetworkEvents<br/>
| where DeviceName contains "ENTITY"<br/>
| where InitiatingProcessFileName contains "powershell"<br/>
| where ActionType !contains "ConnectionFailed"<br/>
| where InitiatingProcessAccountName contains "ENTITY"<br/>
| summarize count() by RemotePort<br/>
```
```
DeviceNetworkEvents<br/>
| where DeviceName contains "ENTITY"<br/>
| where InitiatingProcessFileName contains "powershell"<br/>
| where ActionType contains "ConnectionFailed"<br/>
| where InitiatingProcessAccountName contains "ENTITY"<br/>
| where RemotePort == 3389<br/>
| summarize count() by RemoteIP, RemoteUrl<br/>
| distinct RemoteIP <br/>
```
---

Common Security Logs are a collection of events formatted in the Common Event Format (CEF), typically received from security devices like firewalls from vendors such as Cisco and Palo Alto. These logs are designed to be easily readable and standardized for security information and event management (SIEM) systems, facilitating efficient analysis of security events and threats.

Syslog, on the other hand, is a widely used protocol for logging messages across various systems and network devices. It allows for the centralized collection and monitoring of system messages, including events, errors, warnings, and user activity. This standardization helps IT administrators effectively troubleshoot and manage network and system issues.

While both Syslog and CEF are popular standards for logging and event management, CEF provides a pre-parsed, structured format specifically for security-related events, such as details on source and destination IPs, ports, and protocols. Syslog messages, in contrast, may contain a broader range of system information that requires interpretation.

Common Security Logs<br/>

```
CommonSecurityLog<br/>
| where TimeGenerated > ago(20d)<br/>
| where DeviceVendor contains 'vendor_entity'<br/>
| where Computer contains "ENTITY"<br/>
| summarize count() by bin(TimeGenerated, 5h)<br/>
| render columnchart <br/>
```
```
CommonSecurityLog<br/>
| where TimeGenerated > ago(5d)<br/>
| where DeviceVendor contains 'Palo Alto Networks'<br/>
| summarize arg_max(TimeGenerated, *) , count() by Computer<br/>
| project Computer, TimeGenerated<br/>
| sort by TimeGenerated asc<br/> 
```

Syslog<br/>

```
Syslog<br/>
| project TimeGenerated, Computer, HostIP<br/>
| where TimeGenerated > startofday(ago(90d))<br/>
| summarize count() by bin(TimeGenerated, 5h), Computer <br/>
```
```
Syslog <br/>
| where TimeGenerated > ago(15d) <br/>
| where Computer in ("ENTITY", "ENTITY", "ENTITY") <br/>
| summarize arg_max(TimeGenerated, *) , count() by Computer <br/>
| project Computer, TimeGenerated <br/>
| sort by TimeGenerated asc  <br/>
```
```
union Syslog,CommonSecurityLog<br/>
| where TimeGenerated > ago(14d)<br/>
| summarize count() by bin(TimeGenerated, 10m), Type<br/>
| where Computer contains "ENTITY" <br/>
| render columnchart <br/>
```

---

Heartbeat<br/>

```
Heartbeat<br/>
| where Computer contains "ENTITY"<br/>
| where TimeGenerated > ago(20d)<br/>
| summarize count() by bin(TimeGenerated, 2h)<br/>
```

---

Usage Spike<br/>

```
Usage<br/>
| project TimeGenerated, DataType, Quantity<br/>
| where TimeGenerated > ago(90d)<br/>
| where DataType in ('CommonSecurityLog','AADNonInteractiveUserSignInLogs','SecurityEvent','Syslog','DnsEvents')<br/>
| summarize IngestionVolumeMB=sum(Quantity) by bin(TimeGenerated, 1d), DataType<br/>
| render columnchart <br/>
```
```
Usage <br/>
| where TimeGenerated > startofday(ago(1d)) <br/>
| where StartTime >= startofday(ago(1d)) <br/>
| where IsBillable == true <br/>
| summarize TotalVolumeGB = sum(Quantity) / 1000 by bin(StartTime, 1d) <br/>
| summarize Tot=make_list_if(TotalVolumeGB,StartTime==startofday(ago(1d))) <br/>
| where Tot[0]>200 //threshold.<br/>
| project-rename TotalVolumeRecievedGB=Tot<br/>
```
```
Usage
| where TimeGenerated > startofday(ago(1d))<br/>
| where StartTime >= startofday(ago(1d)) and EndTime <= startofday(now())<br/>
| where IsBillable == true<br/>
| summarize TotalVolumeGB = sum(Quantity) / 1000 <br/>
```






