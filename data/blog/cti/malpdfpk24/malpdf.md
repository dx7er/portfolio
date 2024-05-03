---
title: Pakistan Prime Minister's Office Themed Phishing PDF File Evaded All the AV Solutions
date: '2024-05-03'
tags: ['AV', 'red team', 'MITRE', 'malicious pdf', 'Pakistan', 'prime minister', 'ioc', 'breach']
draft: false
summary: My insights on suspicious file detection that targeted Pakistan PM Office.
---

In the realm of cybersecurity, the detection and analysis of suspicious files is a critical task. In this blog, I will share my insights on a case where a suspicious PDF file evaded all antivirus (AV) systems and targeted the office of the Prime Minister of Pakistan.


### The Incident
Recently, the Prime Minister’s office in Pakistan was targeted by a cyberattack. The attack involved a suspicious PDF file that managed to evade all AV systems, demonstrating the sophistication of the threat actors involved. The incident was analyzed using DocGuard, a leading platform for document analysis and threat detection.

### Analyzing Suspicious PDF Files
Analyzing a suspicious PDF file involves examining, decoding, and extracting the contents of suspicious PDF objects that may be used to exploit a vulnerability. There are several web-based tools available for analyzing suspicious PDFs without having to install any tools. These online tools automate the scanning of PDF files to identify malicious components4.

**Some of these tools include:**
- **PDF Examiner:** This tool scans the uploaded PDF for known exploits, allows the user to explore the structure of the file, and examine, decode, and dump PDF object contents4.
- **Jsunpack:** Designed for automatically examining and deobfuscating JavaScript, Jsunpack can also examine PDF files for malicious JavaScript artifacts4.
- **Wepawet:** An automated tool for identifying malicious client-side components in the form of PDF, Flash, and JavaScript elements4.
- **Gallus:** An online scanner for PDF files, Gallus is able to identify common exploits4.

### DocGuard Analysis Report
The [DocGuard](https://app.docguard.io/23f3a046884bf94ec706f98000a9efbda48455b4dd86f0665409937b1fb811cb/112148fa-67fb-4646-8dcd-9007ddf87e00/0/results/dashboard) analysis report provides comprehensive information about the suspicious file. It allows you to visually see important details such as the various characteristics of the file, the detected techniques, and the MITRE ATT&CK methods through its web interface. In addition, the DocGuard report provides details of IOC. These features allow users to quickly identify potential security threats within the file and take effective action.

1. **General Information**</br>
- **File Name:** Outstanding Payment of Tender upload fee - PPRA.pdf</br>
- **SHA256:** 23f3a046884bf94ec706f98000a9efbda48455b4dd86f0665409937b1fb811cb</br>
- **MD5:** d4eb4cee8aeb6f2ea36afadeda9dbb23</br>

2. **Detections**</br>
These are the Maldoc types and detected ones:</br>

|   Maldoc Types  | Detection   |
| ------------- | ------------- |
| Potential Phishing | Detected |
| Vba Stomping | Not Detected |
| Dde String   | Not Detected |
| Obfuscation  | Not Detected |
|Amsi Scan Result | Not Detected |
|Suspicious Encryption | Not Detected |

>More details can be found [here](https://app.docguard.io/23f3a046884bf94ec706f98000a9efbda48455b4dd86f0665409937b1fb811cb/112148fa-67fb-4646-8dcd-9007ddf87e00/0/results/dashboard)

3. **IOC:**</br>
- URL : https://info.goverment-pk-update.top/29-04-PM-MSG/ **Malicious**
- http[:]//docs.mofa-services-server.top/
- (MD5) 38f96b882363cb659d4cabec49bf605c

4. **File Content:**</br>
![image](./data/blog/cti/malpdfpk24/ppdf1.jpeg)
![image](https://github.com/dx7er/portfolio/assets/79792270/83e4572d-fce9-495a-b0cc-8bf0037fa7e8)
![image](https://github.com/dx7er/portfolio/assets/79792270/c7da13b5-58f4-42b2-a931-016b36a15180)
![image](https://github.com/dx7er/portfolio/assets/79792270/dc61ed0a-7d9f-4d31-a60e-a30635de3325)


### The Threat Landscape
The incident at the Prime Minister’s office is a stark reminder of the evolving threat landscape. Cybercriminals are constantly developing new techniques to evade detection and carry out their malicious activities. In this case, the suspicious PDF file was able to bypass all AV systems, highlighting the need for robust and comprehensive cybersecurity measures.

### Conclusion
In conclusion, the blog post highlights the importance of vigilant cybersecurity practices in the face of increasingly sophisticated cyber threats. The incident involving a phishing PDF file that targeted the Prime Minister’s Office of Pakistan and evaded all antivirus systems underscores the need for advanced threat detection and analysis tools. The incident serves as a reminder that no entity, regardless of its stature, is immune to cyberattacks. Therefore, continuous vigilance, regular system checks, and the use of advanced threat detection tools are crucial in maintaining a robust defense against such threats.
