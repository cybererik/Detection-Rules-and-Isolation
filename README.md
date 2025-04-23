# Incident-Analysis-and-Isolation


<img width="600" alt="image" src="https://github.com/user-attachments/assets/83ba4920-6437-482a-a259-1ccc80849336">


## Overview
This project simulates a real-world cybersecurity incident at CyberEV Consulting, where unauthorized software installation triggers an automated EDR (Endpoint Detection and Response) response. Using Microsoft Defender for Endpoint, the affected VM is automatically isolated after detecting a prohibited application. The incident is then investigated using Kusto Query Language (KQL) for forensic analysis to identify the root cause and assess user intent.

Per company policy, any device isolated by the “No AI Detection” rule must undergo a forensic investigation to determine whether the activity was accidental or indicative of an insider threat. This process uncovered additional suspicious behavior, reinforcing the need for strict policy enforcement and continuous monitoring.

> 🏢 Company Scenario |  Company Name: EV Financial Group | Industry: Financial Services

------
## Tools & Technologies
- **Microsoft Azure** (Virtual Machine Provisioning)
- **Microsoft Defender for Endpoint** (Enterprise EDR)
- **Kusto Query Language** (Log Retrieval)


## Objective(s)
1) **Simulate a security incident involving remote code execution in a corporate environment.**
2) **Automatically isolate a compromised VM using Microsoft Defender for Endpoint.**
3) **Use KQL (Kusto Query Language) to retrieve and analyze Azure logs for forensic analysis.**
4) **Identify the root cause of the alert and track user activity through log data.**

-----
### Step 1: Creating the Detection Rule

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
### Step 2: Verifying Isolation

![Screenshot 2025-04-16 234934](https://github.com/user-attachments/assets/c5ef4e02-8501-4409-9c07-1009f77edf5d)

As shown in the screenshot, the device **remote-agent-er** was automatically isolated based on the custom detection rule.

The investigation uncovered two separate process executions, confirming that the AI generative tool ChatGPT was installed and launched twice on the machine. The activity was tied to the user account **fdvkml345212**, allowing us to attribute the actions to a specific individual.

## 📅 Timeline of Events:
- **First Activity: April 16 at 10:14 PM**
- **Second Activity: April 16 at 11:34 PM**

------

### Step 3: Forensic Investigation 

![DOWNLOADED CHATGBT Screenshot 2025-04-16 231027](https://github.com/user-attachments/assets/9c3fea51-b96b-49e8-a271-7fe26efe4a02)

**KQL Script Explanation** - [Click to View](https://github.com/cybererik/Forensics-Investigation-and-Isolation/blob/main/Detect%20Executable%20File%20Activity%20on%20Remote%20Agent%20Devices)

During the investigation, we saw that **ChatGPT.exe** was installed on the VM. The forensic logs revealed it was installed using a process called:

```kql
svchost.exe -k wsappx -p
```


### 📌 What does this mean?

- `svchost.exe` is a legitimate Windows system process used to run services.
- `wsappx` is a Windows service that handles **Microsoft Store installations and updates.**

The presence of `ChatGPT.exe` and the process details suggest that the **ChatGPT desktop app was installed directly through the Microsoft Store**, not from a browser or a manual download.


### 🧪 Supporting Evidence:

- Files were written to the **Microsoft.WindowsStore** directory.
- Initiating process was `svchost.exe` under the `wsappx` group.
- This matches how Microsoft Store apps are usually installed in the background by system processes.

### Why This Matters:

Although the process looks legitimate, the app itself (ChatGPT) is blocked in this simulated environment due to company policy. The user found a workaround by installing it via the Microsoft Store, bypassing normal security restrictions.

-----
### Step 4: Additional findings
Per company policy, any device isolated by the "No AI detection" rule requires a forensic investigation to determine whether the activity was accidental or the result of potential insider threats.


![Screenshot 2025-04-16 231558](https://github.com/user-attachments/assets/c9063411-2d64-4db7-8ea2-ad7731cf5c38)

### **Explanation of the Command:**

```bash
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait"
```

This activity could indicate an attempt to install software from an external source, which should be investigated further. This command runs a PowerShell script through the command line (cmd.exe). It can be broken down into the following steps:

1. **Invoke-WebRequest**:  
   - Downloads a file from the URL `https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe` and saves it as `7z2408-x64.exe` in the `C:\ProgramData` directory.
   
2. **Start-Process**:  
   - Executes the downloaded file (`7z2408-x64.exe`) from the `C:\ProgramData` folder.  
   - The `-ArgumentList '/S'` part ensures the installer runs silently (without user interaction).  
   - The `-Wait` argument makes PowerShell wait until the installation is complete before proceeding with any further steps.

### **Key Highlights**:
- This command downloads the **7-Zip** installer (`7z2408-x64.exe`) from the internet.
- The installer is saved in the `C:\ProgramData` folder (a common location for system-level software).
- The installer runs silently with the `/S` argument, meaning no user input is required during installation.
- The command executes the file immediately after downloading.

------
## 🧠 Conclusion
This project demonstrated how to simulate and investigate a security incident using **Microsoft Defender for Endpoint** and **Kusto Query Language (KQL)**. By isolating a compromised VM and analyzing logs, we identified that a user bypassed corporate restrictions to install a blocked application via the Microsoft Store. 

The findings highlight the importance of effective **EDR** solutions and forensic analysis in detecting and responding to security incidents. To improve our protections moving forward, we should consider enhancing our alerting mechanisms, adjusting security settings, and potentially disabling the Microsoft Store to prevent unauthorized installations in the future.



