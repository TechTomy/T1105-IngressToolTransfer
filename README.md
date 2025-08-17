# T1105 - Ingress Tool Transfer - certutil download (urlcache)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Microsoft Sentinel
- Kusto Query Language (KQL)
- Atomic Red Team

##  Scenario

Employee JDoe reported slow performance and pop-up errors on JDoe-VM after interacting with a phishing email (“Urgent: Update Your Software License”). The SOC tasked me with hunting for telemetry to identify a potential compromise, focusing on unauthorized tool downloads (MITRE ATT&CK T1105: Ingress Tool Transfer).

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceProcessEvents`** for any events around the moment link was clicked.
- **Check `DeviceFileEvents`** for any signs of file creations around the time of previous events.
- **Check `DeviceNetworkEvents`** for any signs of unusual connections from internal network devices to outside servers.


---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

First step I looked to see if there were any powershell commands/scripts that ran around the time the employee stated he clicked the phishing email requesting he update his software licenses. This led to me finding a powershell command that was leveraging certutil to download a file from a server outside of network. The command `certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt` would leverage built in windows utility CertUtil to download a file and save it as `Atomic-license.txt` Here’s the KQL query that was used to track this down:

**Query used to locate events:**

```kql
let EmployeePC5 = "288ce2859bb70e1407cc0be846f0aad951e344f8";
DeviceProcessEvents
| where DeviceId == EmployeePC5 and ProcessCommandLine contains "certutil"
| where TimeGenerated between ( todatetime('2025-07-30T00:00:00.000000Z').. todatetime('2025-07-30T20:00:00.000000Z'))
| project Timestamp, ProcessCommandLine, InitiatingProcessCommandLine
| sort by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/ae55f712-81c2-4760-9956-2778449bd601">


---

### 2. Searched the `DeviceFileEvents` Table

Upon looking into the `DeviceFileEvents`, there’s no apparent evidence that there was any file created as was attempted. This would indicate that device defenses successfully prevented the malicious code from achieving its intended goal. Below is the KQL query used:

**Query used to locate event:**

```kql
let EmployeePC5 = "288ce2859bb70e1407cc0be846f0aad951e344f8";
DeviceFileEvents
| where DeviceId == EmployeePC5 and FileName contains "atomic-license"
| where TimeGenerated between ( todatetime('2025-07-30T00:00:00.000000Z').. todatetime('2025-07-30T20:00:00.000000Z'))
```

---

### 3. Searched the `DeviceNetworkEvents` For file Creations

Upon verifying network events it’s confirmed that connection was successful with the external server but ultimately there was no file downloaded/created. The evidence suggests that malicious code was not able to download the files needed to continue its intended purpose.

```kql
let EmployeePC5 = "288ce2859bb70e1407cc0be846f0aad951e344f8";
DeviceNetworkEvents
| where DeviceId == EmployeePC5 and InitiatingProcessFileName == "certutil.exe"
| where TimeGenerated between ( todatetime('2025-07-30T00:00:00.000000Z').. todatetime('2025-07-30T20:00:00.000000Z'))
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/4018c481-8369-4df1-b615-3fb4d581c907">

---

## Response Taken

I concluded that the malicious actor hadn’t gotten a host to run the command but did manage to connect to their server. We quarantined the device and have begun remediating all potential vulnerabilities.

---
## MITRE ATT&CK TTPs:

<br/>- T1566.001 - Phishing: Spearphishing Attachment
<br/>- T1059.001 - Command and Scripting Interpreter: PowerShell
<br/>- T1105 - Ingress Tool Transfer
<br/>- T1218.011 - System Binary Proxy Execution: CertUtil

---
