# KQL

**My Go-To Microsoft Queries**

Over the last three years, I've relied on these queries to help me efficiently search, analyze, and react to all alerts and events I encountered as a SIEM technician and SOC analyst. Knowing KQL (Kusto Query Language) is a very important skill for all professionals working on Microsoft environments. 

You don't need super advanced and lengthy queries to find the information you need; often, starting with a simple search or listing all the tables can give you a sense of how many logs are related to the specific term you're searching for. Over time, you'll become familiar with which tables are relevant for certain alerts or information and which ones might not be as useful. If you encounter a table with a large number of alerts, you can refine your search by adding more filters based on the columns available in that table. With time and experience you will be able to gradually build your own KQL library too. 

I listed below all KQL queries I use on my day to day; however, you can find the complete information of all tables and its use cases under the official Microsoft documentation about KQL and advanced hunting schema.

**Kusto Query Language overview:**
https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric

**KQL quick reference:**
https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference?view=microsoft-fabric

**Understand the advanced hunting schema:**
https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables

![image alt](https://github.com/dita-cyber/KQL/blob/0e11a3555d762f49193e4d6a36d82df83e976138/kql11.png) 

---

**General search**

The search function is my starting point for a broad exploration across all tables. It allows me to identify the presence of specific entities across the dataset and list all tables that specific term shows for the time range I have defined.

```
search "ENTITY"
| summarize count() by $table 
```

I also use this query below if I want to search all tables containing more than one keyword:

```
search "ENTITY1" and "ENTITY2"
| summarize count() by $table
```
---
**Security Events**

SecurityEvent table show all the security events collected from windows machines by Azure Security Center or Azure Sentinel. This is a good resource for investigating processes, command lines, file paths, and parent processes associated with a specific process on a host.

```
SecurityEvent
| where Computer contains "ENTITY"
| where * contains "PROCESS"
| project-reorder TimeGenerated, Activity, Process, CommandLine, FileHash,  FilePath, NewProcessName, ParentProcessName, SubjectAccount
```
---

**Logins**<br/>

SigninLogs table help me with tracking user login activities. It provides detailed information on login attempts, including user details and location data.  

Difference between SigninLogs and AADNonInteractiveUserSignInLogs

**SigninLogs:** User-driven sign-ins, where the user directly interacts with the login process. <br/>
**AADNonInteractiveUserSignInLogs:** Sign-ins performed by applications or systems on behalf of a user, without user interaction. 

From my experience I found the most useful collumns for SigninLogs table are:

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
SigninLogs
| where TimeGenerated > ago(30d) 
| where * contains "ENTITY" 
| project TimeGenerated, UserPrincipalName, UserDisplayName, Location, LocationDetails, IPAddress, Status, ConditionalAccessStatus, AuthenticationRequirement, AuthenticationDetails, ResultType, ResultDescription, UserAgent, MfaDetail, AppDisplayName, DeviceDetail 
| sort by TimeGenerated 
```
```
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "ENTITY"
| extend DeviceName = parse_json(DeviceDetail).displayName
| extend TrustType = parse_json(DeviceDetail).trustType
| extend Browser = parse_json(DeviceDetail).browser
| extend City = parse_json(LocationDetails).city
| extend Country = tostring(parse_json(LocationDetails).countryOrRegion)
| extend StatusDetails = tostring(parse_json(Status).additionalDetails)
| project TimeGenerated, AppDisplayName,DeviceName, TrustType, Browser, IPAddress ,AuthenticationRequirement,StatusDetails, ClientAppUsed, City
```
```
AADNonInteractiveUserSignInLogs
| where not(ResultType in (50126, 50053)) 
| where ClientAppUsed == "Other clients" and UserAgent == "fasthttp"
| where ResultType in (_SuccessResultTypes) or AuthenticationDetails has 'succeeded":true'
| project-reorder CreatedDateTime, Category, UserPrincipalName, AlternateSignInName, IPAddress, Location, AutonomousSystemNumber, ResultType, ResultDescription, AuthenticationDetails, AppDisplayName, UserAgent, AppId, UserId, OriginalRequestId, CorrelationId
```
---

**IdentityInfo**<br/>

IdentityInfo table is related to Azure Sentinel UEBA with all your users identities information. I like to use this table to correlate user data, for instance, if I only have a user's SID, I can utilize this table to identify the user, explore associated groups, and gather detailed information about the user's account.

```
IdentityInfo
| where * contains "S-1-5-21-________-_________-________-_____"
```

---

**Audit Logs**<br/>

The Audit Logs table provides a detailed record of changes within Azure Active Directory (Azure AD), capturing activities such as user creation, group additions, and modifications across the Azure AD environment. It also includes entries from Azure AD Privileged Identity Management. This table helps verifyind user account compromise investigations, validating password changes, tracking new devices added to MFA, monitoring password resets, and checking when accounts are disabled or enabled. By cross-referencing this data with other sources, I gain deeper insights and enhance correlation for a more comprehensive understanding of security events accross an environment. 

```
AuditLogs
| where TimeGenerated >= ago(15d) 
| where OperationName == "Change user password"
| where TargetResources[0].userPrincipalName == "ENTITY"  
```

---

**Office Activity**<br/>

The OfficeActivity table is the central repository for all Office 365-related events, capturing logs from applications like Microsoft Exchange 365, Microsoft SharePoint 365, and OneDrive. It includes both operational and audit events, making it a rich source of information for monitoring user activity. I leverage this table to investigate scenarios such as high download volumes, which might indicate potential data exfiltration or extensive OneDrive sync events. The detailed logs allow me to examine the user agent, file extensions, and file paths.

```
OfficeActivity 
| search "ENTITY" or "ENTITY" 
| where Operation == "OPERATION"
```

---

**Alert Evidence**<br/>

The AlertEvidence table, part of the advanced hunting schema, provides information about various entities, such as files, IP addresses, URLs, users, and file hashed to alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Defender for Cloud Apps, and Microsoft Defender for Identity. This table is an excellent resource for constructing queries that extract detailed information on security alerts. I usually use it to verify whether a file hash has been successfully blocked, as indicated by the "remediated status: prevented" field, along with the associated timestamp.

```
AlertEvidence
| where * contains "ENTITY"
```

---

**Emails and Attachments**<br/>

EmailEvents can be used to detect and investigate suspicious inbox manipulation rules. Look for events with ActionType values indicating the creation or modification of inbox rules (e.g., "New-InboxRule", "Set-InboxRule"). Some examples of suspicious behavior:
- Forwarding to unknown or untrusted recipient <br/>
- Moving emails to a hidden or deleted folders <br/>
- Marking emails as read to avoid detection <br/>
- Filtering by keywords: analyze the keywords used in the rule's filters <br/>
- Absence of filtering could also be suspiciou <br/>

```
EmailEvents 
| search "ENTITY" 
```
```
EmailEvents
| search "ENTITY"
| project-reorder TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, NetworkMessageId
| where * contains "KEYWORD"
```
```
EmailAttachmentInfo 
| where * contains "ENTITY"
```
---

**URL Clicks**

Events involving URLs clicked, selected, or requested on Microsoft Defender for Office 365.

```
UrlClickEvents
| where url contains "ENTITY"
```

---

**LDAP**

IdentityQueryEvents is a table in the advanced hunting schema that logs LDAP queries performed against domain controllers. This table provides visibility into the LDAP search queries running the environment and can help detect potential reconnaissance or other malicious activities. It records details such as the query itself, the target object, and the source of the query (e.g., IP address, user account). 

```
IdentityQueryEvents
| where TimeGenerated > ago(30d)
| search "ENTITY" and "ENTITY"
| where QueryType !contains "NS"
| where QueryType !contains "srv"
```

---

**Device Events**<br/>

This table is an integral component of Microsoft Defender for Endpoints integrated with Azure Sentinel. It contains a diverse range of event types, including those triggered by security controls such as Windows Defender Antivirus and exploit protection.

To gather comprehensive insights about a specific host or term, I utilize a union of the DeviceEvents table with other related Device tables, such as:

DeviceNetworkEvents: Provides detailed information about network connections and related activities.<br/>
DeviceFileEvents: Contains data on file creation, modifications, and other file system events.<br/>
DeviceProcessEvents: Identifies the logon session of the process that initiated the event, offering insights into process activities.<br/>

By combining these tables, I can efficiently collect and analyze information from multiple sources to save time instead of searching table by table.

```
DeviceEvents
| where DeviceName contains "ENTITY" 
```
```
DeviceNetworkEvents 
| where DeviceName contains "ENTITY" 
| where InitiatingProcessFileName contains "powershell"
| where ActionType !contains "ConnectionFailed" 
| where InitiatingProcessAccountName contains "ENTITY" 
| summarize count() by RemotePort 
```
```
union DeviceEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceProcessEvents
| where TimeGenerated > ago(2d)
| where DeviceName has "ENTITY"
| project-reorder TimeGenerated, Type, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemoteIPType
```
---

**Common Security Logs and Syslog**<br/>

Common Security Logs are a collection of events formatted in the Common Event Format (CEF), typically received from security devices like firewalls from vendors such as Cisco and Palo Alto. These logs are designed to be easily readable and standardized for SIEM systems, facilitating efficient analysis of security events and threats.

Syslog, on the other hand, is a widely used protocol for logging messages across various systems and network devices. It allows for the centralized collection and monitoring of system messages, including events, errors, warnings, and user activity. This standardization helps IT administrators effectively troubleshoot and manage network and system issues.

While both Syslog and CEF are popular standards for logging and event management, CEF provides a pre-parsed, structured format specifically for security-related events, such as details on source and destination IPs, ports, and protocols. Syslog messages, in contrast, may contain a broader range of system information that requires interpretation.

**Common Security Logs**<br/>

```
CommonSecurityLog
| where TimeGenerated > ago(20d)
| where DeviceVendor contains "VENDOR"
| where Computer contains "ENTITY"
| summarize count() by bin(TimeGenerated, 5h)
| render columnchart 
```
```
CommonSecurityLog
| where TimeGenerated > ago(5d)
| where DeviceVendor contains "VENDOR"
| summarize arg_max(TimeGenerated, *) , count() by Computer
| project Computer, TimeGenerated
| sort by TimeGenerated asc
```

**Syslog**<br/>

```
Syslog
| project TimeGenerated, Computer, HostIP
| where TimeGenerated > startofday(ago(90d))
| summarize count() by bin(TimeGenerated, 5h), Computer 
```
```
Syslog 
| where TimeGenerated > ago(15d) 
| where Computer in ("ENTITY", "ENTITY", "ENTITY") 
| summarize arg_max(TimeGenerated, *) , count() by Computer 
| project Computer, TimeGenerated 
| sort by TimeGenerated asc  
```
```
union Syslog,CommonSecurityLog
| where TimeGenerated > ago(14d)
| summarize count() by bin(TimeGenerated, 10m), Type
| where Computer contains "ENTITY" 
| render columnchart 
```

---

**Heartbeat**<br/>

It shows records logged by Log Analytics agents once per minute to report on agent health for a specific host. It is useful to check if hosts are up and running and troubleshoot connectivity and log ingestion disruption. 

```
Heartbeat
| where Computer contains "ENTITY"
| where TimeGenerated > ago(20d)
| summarize count() by bin(TimeGenerated, 2h)
```

---

**Usage**<br/>

It gives information about data ingestion and usage within your Log Analytics workspace, including billable data. It is useful to understand data spikes for certain logs. 

```
Usage
| project TimeGenerated, DataType, Quantity
| where TimeGenerated > ago(90d)
| where DataType in ('CommonSecurityLog','AADNonInteractiveUserSignInLogs','SecurityEvent','Syslog','DnsEvents')
| summarize IngestionVolumeMB=sum(Quantity) by bin(TimeGenerated, 1d), DataType
| render columnchart 
```
```
Usage 
| where TimeGenerated > startofday(ago(1d)) 
| where StartTime >= startofday(ago(1d)) 
| where IsBillable == true 
| summarize TotalVolumeGB = sum(Quantity) / 1000 by bin(StartTime, 1d) 
| summarize Tot=make_list_if(TotalVolumeGB,StartTime==startofday(ago(1d))) 
| where Tot[0]>200 
| project-rename TotalVolumeRecievedGB=Tot
```
```
Usage
| where TimeGenerated > startofday(ago(1d))
| where StartTime >= startofday(ago(1d)) and EndTime <= startofday(now())
| where IsBillable == true
| summarize TotalVolumeGB = sum(Quantity) / 1000 
```






