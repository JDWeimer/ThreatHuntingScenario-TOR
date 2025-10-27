---

# Threat Hunt Report: Unauthorized TOR Usage

### In this project, I simulated a threat hunting scenario involving the unauthorized installation and use of TOR browser in a fictional enterprise environment.

###### This project was done as part of [Josh Madakor's Cyber Range](http://joshmadakor.tech/cyber-range) program.

---

## Scenario Creation
> To create the scenario for the threat hunt, I created a Windows 11 virtual machine in Microsoft Azure (`jvmedr`) and onboarded it to Microsoft Defender for Endpoint. I then simulated the activities of a user taking unauthorized actions by downloading TOR browser, installing it silently via the command line, and browsing to a few sites on the dark web. Finally, I created a text file where I noted down some fictional purchases made, then deleted the text file. Acting as a novice misbehaving user, I neglected to uninstall TOR browser or attempt to further cover my tracks.

## Scope Limitation
> Due to the shared nature of the cyber range environment, in order to limit the scope of the threat hunt to the single VM, all KQL queries were limited to the `jvmedr` device by starting all queries with the following and then searching the in-scope logs:
```kql
let scope_target = "jvmedr";
let InScopeDeviceFileEvents = DeviceFileEvents
| where DeviceName == scope_target;
let InScopeDeviceProcessEvents = DeviceProcessEvents
| where DeviceName == scope_target;
let InScopeDeviceNetworkEvents = DeviceNetworkEvents
| where DeviceName == scope_target;
```

## Platforms and Languages Leveraged
> - [Windows 11 Virtual Machines (Microsoft Azure)](https://azure.microsoft.com/en-us/)
> - [EDR Platform: Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint/)
> - [Kusto Query Language (KQL)](https://learn.microsoft.com/en-us/kusto/)
> - [Tor Browser](https://www.torproject.org/)

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

---

##  Scenario
> Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan
> - **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
> - **Check `DeviceProcessEvents`** for any signs of installation or usage.
> - **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table For TOR Presence
> Searched for any file that had the string "tor" or "firefox" in it and discovered a number of events. However, given that "tor" is a very common string to find in other words often used in file names, the query returned far more events than was useful.
```kql
let target_string_1 = "tor";
let target_string_2 = "firefox";
InScopeDeviceFileEvents
| where FileName contains target_string_1
    or FileName contains target_string_2
| order by Timestamp desc
```
<img width="1136" height="357" alt="image" src="https://github.com/user-attachments/assets/70d5b24a-0ed0-45ca-9ec8-b2fb1d247a9e" />

> Because of this, a list of filters were added to the query to exclude results which included words containing strings which would not be an IoC, and the results were projected to make them easier to review. This revealed what appeared to be evidence that the user "jvmedr-james" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-09-20T18:38:06.9046318Z`. These events began at `2025-09-20T18:29:37.1623729Z`.
```kql
let target_string_1 = "tor";
let target_string_2 = "firefox";
let Results = InScopeDeviceFileEvents
| where FileName contains target_string_1
    or FileName contains target_string_2
| where FileName !contains "storage" and FileName !contains "store" and FileName !contains "inventory" and FileName !contains "tutorial" and FileName !contains "protector" and FileName !contains "collector" and FileName !contains "vector" and FileName !contains "validator" and FileName !contains "origin" and FileName !contains "history" and FileName !contains "factory" and FileName !contains "storm" and FileName !contains "editor" and FileName !contains "accelerator" and FileName !contains "monitor" and FileName !contains "adaptor" and FileName !contains "executor" and FileName !contains "aggregator" and FileName !contains "connector" and FileName !contains "calculator" and FileName !contains "indicator" and FileName !contains "repository" and FileName !contains "director" and FileName !contains "emulator" and FileName !contains "redirector" and FileName !contains "creator" and FileName !contains "evaluator" and FileName !contains "generator" and FileName !contains "selector" and FileName !contains "story" and FileName !contains "stories" and FileName !contains "narrator" and FileName !contains "predictor"
| order by Timestamp desc;
Results
| project Timestamp, RequestAccountName, ActionType, FileName, FolderPath
```
<img width="904" height="340" alt="image" src="https://github.com/user-attachments/assets/f4218af4-cc8a-46be-be03-fc57a7b21965" />

### 2. Searched the `DeviceProcessEvents` Table For TOR Browser Installation
> Searched for any `FileName` or `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.7.exe". Based on the logs returned, at `2025-09-20T18:30:59.8565865Z`, the user `jvmedr-james` on the `jvmedr` device ran the file `tor-browser-windows-x86_64-portable-14.5.7.exe` from their Desktop folder, using a command that triggered a silent installation with `/S`.
>
**Query used to locate event:**
```kql
let target_string = "tor-browser-windows-x86_64-portable-14.5.7.exe";
let Results = InScopeDeviceProcessEvents
| where FileName contains target_string
    or ProcessCommandLine contains target_string
| order by Timestamp desc;
Results
| project Timestamp, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, AdditionalFields
```
<img width="1135" height="307" alt="image" src="https://github.com/user-attachments/assets/dbb9549f-3ebb-48bf-8caf-6df3bae38691" />

### 3. Searched the `DeviceProcessEvents` Table For TOR Browser Execution
> Searched for any indication that user `jvmedr-james` actually opened the TOR browser. There was evidence that they did open it at `2025-09-20T18:31:11.3844116Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.
**Query used to locate events:**
```kql
let target_string_1 = "tor.exe";
let target_string_2 = "firefox.exe";
let Results = InScopeDeviceProcessEvents
| where ProcessCommandLine contains target_string_1
    or ProcessCommandLine contains target_string_2
| order by Timestamp desc;
Results
| project Timestamp, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, AdditionalFields
```
<img width="1139" height="361" alt="image" src="https://github.com/user-attachments/assets/168add24-1529-470a-a4fe-53e338b25de9" />

### 4. Searched the `DeviceNetworkEvents` Table For TOR Network Connections
> Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At many points beginning at `2025-09-20T18:32:36.7549452Z`, the user `jvmedr-james` on the `jvmedr` device successfully established a connection to remote IP addresses on known TOR ports. The connections were initiated by the process `tor.exe`, located in the folder `c:\users\jvmedr-james\desktop\tor browser\browser\torbrowser\tor\tor.exe`.
**Query used to locate events:**
```kql
let target_processes = dynamic(["tor.exe", "firefox.exe"]);
let target_ports = dynamic(["9001", "9030", "9040", "9050", "9051", "9150", "80", "443"]);
let Results = InScopeDeviceNetworkEvents
| where RemotePort in (target_ports)
    and InitiatingProcessFileName in (target_processes)
| order by Timestamp desc;
Results
| project Timestamp, InitiatingProcessAccountName, ActionType, LocalIP, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1146" height="334" alt="image" src="https://github.com/user-attachments/assets/dbd0e721-8875-43f3-beab-cf0489cf73a3" />


---

## Chronological Event Timeline 
### 1. File Download - TOR Installer
> - **Timestamp:** `2025-09-20T18:29:58.4674992Z`
> - **Event:** The user `jvmedr-james` downloaded a file named `tor-browser-windows-x86_64-portable-14.5.7.exe` to the Downloads folder, and moved it to the Desktop.
> - **Action:** File download detected.
> - **File Path:** `C:\Users\jvmedr-james\Downloads\tor-browser-windows-x86_64-portable-14.5.7.exe`

### 2. Process Execution - TOR Browser Installation
> - **Timestamp:** `2025-09-20T18:30:59.8565865Z`
> - **Event:** The user `jvmedr-james` executed the file `tor-browser-windows-x86_64-portable-14.5.7.exe` in silent mode, initiating a background installation of the TOR Browser.
> - **Action:** Process creation detected.
> - **Command:** `tor-browser-windows-x86_64-portable-14.5.7.exe /S`
> - **File Path:** `C:\Users\jvmedr-james\Desktop\tor-browser-windows-x86_64-portable-14.5.7.exe`

### 3. Process Execution - TOR Browser Launch
> - **Timestamp:** `2025-09-20T18:31:11.3844116Z`
> - **Event:** User `jvmedr-james` opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
> - **Action:** Process creation of TOR browser-related executables detected.
> - **File Path:** `C:\Users\jvmedr-james\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network
> - **Timestamp:** `2025-09-20T18:32:36.7549452Z`
> - **Event:** A network connection to IP `23.92.34.118` on port `443` by user `jvmedr-james` was established using `tor.exe`, confirming TOR browser network activity.
> - **Action:** Connection success.
> - **Process:** `tor.exe`
> - **File Path:** `c:\users\jvmedr-james\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity
> - **Timestamps:** Between `2025-09-20T18:32:38.5129773Z` and `2025-09-20T18:34:52.9511263Z`.
> - **Event:** Additional TOR network connections were established, indicating ongoing activity by user `jvmedr-james` through the TOR browser.
> - **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List
> - **Timestamp:** `2025-09-20T18:38:06.9046318Z`
> - **Event:** The user `jvmedr-james` created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
> - **Action:** File creation detected.
> - **File Path:** `C:\Users\jvmedr-james\Desktop\tor-shopping-list.txt`

---

## Summary
> The user `jvmedr-james` on the `jvmedr` device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken
> TOR usage was confirmed on the endpoint `jvmedr` by the user `jvmedr-james`. The device was isolated, and the user's direct manager was notified.

---
