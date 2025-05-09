<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joelyim/threat-hunting-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered what looks like the user downloaded a Tor installer, did something that resulted in many Tor-related files being copied to the desktop, and the creation of a file called "tor-shopping-list.txt" on the desktop. These events began at `2025-05-06T01:18:53.8975761Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "joel-testing"
| where InitiatingProcessAccountDomain contains "joel-testing"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-05-06T01:18:53.8975761Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![Screenshot 2025-05-08 183622](https://github.com/user-attachments/assets/cf042666-43b9-438c-b882-6e56d694eff8)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string, `tor-browser-windows-x86_64-portable-14.5.1.ex`. Based on the log returned on May 6th, 2025, at 1:21 PM, a user on the computer named "joel-testing" ran a program called `tor-browser-windows-x86_64-portable-14.5.1.exe` directly from their Downloads folder. This action launched the portable version of the Tor Browser, which allows anonymous browsing without installing the software. The system recorded the exact file fingerprint using SHA-256 to track or verify the file later. No special commands or arguments were used, just a straightforward file execution.

 
**Query used to locate event:**

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows"
| where DeviceName contains "joel-testing"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
![Screenshot 2025-05-08 184044](https://github.com/user-attachments/assets/44841f4b-72ce-421b-b9be-a38e2d3af6fe)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user opened the Tor browser. There was evidence that they did open it at 
`2025-05-06T01:22:43.9180733Z`. Several other instances of Firefox.exe (Tor) and tor.exe spawned afterwards. 


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "joel-testing"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![Screenshot 2025-05-08 184849](https://github.com/user-attachments/assets/d4214ab7-3e49-49c5-8fc0-e945ca053c24)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the Tor Browser was used to establish a connection using any of the known ports. At 2025-05-06T01:23:03.3489314Z, just over a minute after launching the Tor Browser, a network connection to the IP address 217.160.247.34 over port 9001 was established. This connection was associated with the URL https://www.xte5vlo.com, which may be part of the Tor network's entry node infrastructure or a relay. The log indicates the connection attempt was successful, suggesting the browser was actively reaching out to begin anonymized communication. There were a few other connections.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "joel-testing"
| where InitiatingProcessAccountName contains "Joel"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```

![Screenshot 2025-05-08 190935](https://github.com/user-attachments/assets/351753fa-e717-4702-ab51-b6356a28a75f)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-06T01:18:53.8975761Z`
- **Event:** The user downloaded a file named `tor-browser-windows-x86_64-portable-14.5.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Joel\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 2. Process Execution - TOR Browser Installation/Launch

- **Timestamp:** `2025-05-06T01:21:00Z` (approximate from screenshot)
- **Event:** The user executed the file `tor-browser-windows-x86_64-portable-14.5.1.exe`, initiating the portable version of TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.1.exe` 
- **File Path:** `C:\Users\Joel\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 3. Process Execution - TOR Browser Components Launch

- **Timestamp:** `2025-05-06T01:22:43.9180733Z`
- **Event:** TOR browser components were launched. Processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Joel\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-06T01:23:03.3489314Z`
- **Event:** A network connection to IP `217.160.247.34` on port `9001` was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **URL:** `https://www.xte5vlo.com`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:** Various between `2025-05-06T01:23:03Z` and `2025-05-06T01:24:00Z`
- **Event:** Additional TOR network connections were established, indicating ongoing activity through the TOR browser.
- **Action:** Multiple successful connections detected.
- **Remote Ports:** Various including 9001, 443

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-06T01:27:00Z` (approximate based on timeline)
- **Event:** A file named `tor-shopping-list.txt` was created on the desktop, potentially indicating a list or notes related to TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Joel\Desktop\tor-shopping-list.txt`

---

## Summary

A user on the "joel-testing" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created a file named `tor-shopping-list.txt` on their desktop. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `joel-testing`. The device was isolated, and the user's direct manager was notified of the policy violation.

---
