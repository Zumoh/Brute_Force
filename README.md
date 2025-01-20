# Brute_Force

This investigation focused on analyzing network traffic and system logs to identify a Brute Force Attack on a compromised web server, uncovering the attacker's tactics, the targeted server, and compromised credentials, as well as completing a challenge provided by LetsDefend.io.

#

<img width="650" alt="Screenshot 2025-01-19 203716" src="https://github.com/user-attachments/assets/9b90444a-246b-4813-8697-b8fa22ec35af" />


## Objective

This investigation analyzes and identifies the details of a Brute Force Attack on a compromised web server. The goal is to uncover critical information such as the targeted server IP, affected directory, compromised credentials, and the number of failed login attempts. By examining network traffic using Wireshark and reviewing system logs with CLI tools, the investigation aims to identify the attacker’s actions, assess the extent of the breach, and map the attack technique to the MITRE ATT&CK framework.

### Skills Learned

- **Network Traffic Analysis**:
   - Proficient use of Wireshark to capture and analyze network traffic.
      Understanding protocols like HTTP, RDP, and TCP/IP is essential for identifying attack patterns like brute force attempts and unauthorized access. This skill is critical for detecting threats and vulnerabilities in network communication.
- **Log File Analysis:**
   - Expertise in examining system logs (e.g., auth.log) and extracting relevant details.
      - Familiarity with tools like grep, wc, and cat for filtering and processing log files is key to identifying authentication attempts, system anomalies, and potential intrusions. This skill is fundamental for forensic analysis in incident response.
- **Incident Response:**
   - Ability to identify attack tactics and techniques.
      - Analyzing network traffic and logs helps trace the attacker's actions, assess the breach's scope, and formulate a response strategy. This skill is vital for mitigating attacks and protecting systems from further compromise.
- **MITRE ATT&CK Framework:**
   - Understanding and applying the MITRE ATT&CK framework to map attack techniques.
      - Identifying attack patterns and tactics used by adversaries allows for effective threat detection and response. This knowledge is crucial for cybersecurity professionals when defending against known attack vectors.
- **File Extraction and Management:**
   -  Experience in extracting and managing files using tools like 7-Zip.
      - Unzipping encrypted or compressed files, extracting relevant investigation data, and managing files for analysis are essential skills for effective data handling in cybersecurity investigations.
    
### Tools Used

- **Wireshark**: For network packet analysis.
- **7-Zip (7za)**: For extracting files from a compressed archive.
- **Command Line Interface (CLI)**: For navigating the system and processing files.

- **MITRE ATT&CK**: For identifying techniques and their associated **Mitre ID**.

### Preparation

From the command line we navigate to the directory that has the folder we need for our investigation.

```cd Desktop/ChallengeFile```

#

<img width="650" alt="Screenshot 2025-01-19 203716" src="https://github.com/user-attachments/assets/6278bdda-c47e-4006-822b-3f69c5d52496" />

#

Since the folder is zipped, we first have to unzip the folder to have access to the files it contains.
To do this, we use the following command:
```7za x BruteForce.7z```
- 7za - This is the command-line utility for 7-Zip, used for file compression and extraction.
- x - This option tells 7za to extract the files from the archive.
- BruteForce.7z - This is the name of the zipped folder you want to unzip.

When prompted for the password, I entered 'infected' to proceed with the extraction.

#

<img width="650" alt="Screenshot 2025-01-19 211335" src="https://github.com/user-attachments/assets/f02b2028-7f0c-4296-a4be-d982bcd4a613" />

#

We use the ls command to list the contents of the unzipped directory. This command displays the files and subdirectories within the specified directory, providing a quick overview of its structure and contents. By running ls, you can verify that the files have been successfully extracted and are accessible for further analysis.

#





