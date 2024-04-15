---
title: Hide Backdoors in Scheduled Tasks
date: '2024-03-15'
tags: ['backdoor', 'read team', 'hacking', 'red team tips', 'scheduled tasks', 'hacking', 'techniques', 'tips']
draft: false
summary: Tip to hide backdoor in Scheduled Tasks.
---



### Scheduled Tasks.

Scheduled tasks in Windows allow you to automate the execution of programs or scripts at specific times or in response to certain events. These tasks can include system maintenance, application updates, backups, or any other operation that needs to be performed on a regular basis without manual intervention. Scheduled tasks can potentially be misused to hide a backdoor on a system by employing techniques that allow the backdoor to evade detection or execute at specific times to avoid suspicion.


### Usage of Schduled Tasks.

- **Stealth Execution:** A backdoor can be configured to run as a scheduled task with a name that appears benign or inconspicuous, making it less likely to be noticed by users or security software.
- **Randomized Execution Times:** Scheduled tasks can be set to execute at random or uncommon times to evade detection. By avoiding predictable patterns, the backdoor can operate stealthily without raising suspicion.
- **Dynamic Payload:** The scheduled task can be configured to download or update the backdoor's payload from an external server at regular intervals, making it harder to detect as the payload itself may change frequently.
- **Low Priority:** Assigning the scheduled task a low priority can ensure that it operates in the background without interfering with the normal operation of the system, further reducing the likelihood of detection.
- **Conditional Execution:** The backdoor can be programmed to execute only under specific conditions, such as when certain files or processes are present on the system, to avoid detection by antivirus or other security software that relies on signatures or behavior analysis.

### Evasion Technique.
>The SD `Security Descriptor`, essentially an Access Control List (ACL), dictates which users can access the scheduled task. By removing this descriptor, we effectively render the task invisible to all users, including administrators. Windows only displays tasks that users have permission to use, so restricting access conceals our activity.

- **Locate the SDs:** All scheduled tasks' security descriptors are stored in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. Each task has a corresponding registry key containing an `SD` value.
- **Erase the SD:** Only with `SYSTEM privileges` can you delete these values. Use tools like `psexec` to open Regedit with SYSTEM access.
- **Remove the SD for our Task:** Target the `Backdoor` task and delete its SD value. ![image](https://github.com/dx7er/portfolio/assets/79792270/32bda00d-469e-447b-a99a-c0e1387f7a75)

>This maneuver ensures our task remains hidden, evading detection even under scrutiny.

--- 
### If you like this blog do follow me on [GitHub](https://github.com/dx7er), [LinkedIn](https://www.linkedin.com/in/naqvio7/). A supporter is worth a thousand followers [Buy Me a Coffee](https://www.buymeacoffee.com/dx73r).
