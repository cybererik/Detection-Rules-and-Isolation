# Forensics-Investigation-and-Isolation

<img width="1000" alt="image" src="https://github.com/user-attachments/assets/403abdde-34d1-4396-beb6-e62b773d6e89">

## Overview
This project simulates a real-world corporate incident where a user triggers an EDR rule in Microsoft Defender for Endpoint. The rule detects suspicious behavior and automatically isolates the affected VM. We provisioned the VM in Microsoft Azure, onboarded it to Defender, and used KQL to query logs for forensic analysis. The goal was to investigate what caused the alert and determine if the user's actions were malicious by further analyzing their activity through logs.

## Tools & Technologies
- **Microsoft Azure** (Virtual Machine Provisioning)
- **Microsoft Defender for Endpoint** (Enterprise EDR)
- **Kusto Query Language** (Log retrival)


## Objective(s)
1) **Simulate a security incident involving remote code execution in a corporate environment.**
2) **Automatically isolate a compromised VM using Microsoft Defender for Endpoint.**
3) **Use KQL (Kusto Query Language) to retrieve and analyze Azure logs for forensic investigation.**
4) **Identify the root cause of the alert and track user activity through log data.**

-----
## Project Overview

### Step 1: Provisioning the Virtual Machine (The target VM)
1. Create a new Virtual Machine (VM) on **Microsoft Azure** with Windows 10 Pro as the OS.
2. Onboarding the VM to Microsoft Defender for Endpoint

------
### Step 2: Creating the Detection Rule

![Screenshot 2025-04-16 234248](https://github.com/user-attachments/assets/cbb7334e-cff9-4842-9915-26e404989af5)

We created a detection rule in Microsoft Defender for Endpoint to alert and isolate any device running ChatGPT.exe. In this scenario, the organization blocks generative AI tools like ChatGPT due to data privacy risks associated with cloud-based uploads.

### 💡 KQL Query – ChatGPT Installation Detection
```kql
DeviceProcessEvents
| where FileName has "ChatGPT.exe"
  or ProcessCommandLine has "ChatGPT"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, FolderPath, ReportId
| order by Timestamp desc
```


------
### Step 3: Verifying Isolation

![Screenshot 2025-04-16 234934](https://github.com/user-attachments/assets/c5ef4e02-8501-4409-9c07-1009f77edf5d)

As shown in the screenshot, the device remote-agent-er was automatically isolated based on the custom detection rule.

The investigation uncovered two separate process executions, confirming that the AI generative tool ChatGPT was installed and launched twice on the machine. The activity was tied to the user account fdvkml345212, allowing us to attribute the actions to a specific individual.

## 📅 Timeline of Events:
- **First Activity: April 16 at 10:14 PM**
- **Second Activity: April 16 at 11:34 PM**

------
### Step 4: Forensic Investigation 

Per company policy, any device isolated by the "No AI detection" rule requires a forensic investigation to determine whether the activity was accidental or the result of potential insider threats.

![DOWNLOADED CHATGBT Screenshot 2025-04-16 231027](https://github.com/user-attachments/assets/9c3fea51-b96b-49e8-a271-7fe26efe4a02)

**KQL Script** - [Click to View](https://gist.github.com/cybererik/06952c7132cf3ccbce68c1dda8a93c11)

**📄 What This KQL Query Does (in simple terms)**

This KQL query looks for **.exe files** that were either created or written on devices whose name starts with **"remote-agent-er"** (the VM in question). It pulls data from the **DeviceFileEvents** table in Microsoft Defender for Endpoint.

The query shows:
- **When the file activity happened** (Timestamp)
- **Which device it happened on** (DeviceName)
- **The file's name and location** (FileName, FolderPath)
- **What process created or wrote the file** (InitiatingProcessFileName, InitiatingProcessCommandLine)
- **The ReportId to trace the event in the system**

-----
### Step 4: Additional findings
