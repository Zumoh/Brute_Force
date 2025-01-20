# Brute Force Attack Investigation

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

<img width="784" alt="Screenshot 2025-01-19 203716" src="https://github.com/user-attachments/assets/6278bdda-c47e-4006-822b-3f69c5d52496" />

#

Since the folder is zipped, we first have to unzip the folder to have access to the files it contains.
To do this, we use the following command:
```7za x BruteForce.7z```
- **7za** - This is the command-line utility for 7-Zip, used for file compression and extraction.
- **x** - This option tells 7za to extract the files from the archive.
- **BruteForce.7z** - This is the name of the zipped folder you want to unzip.

When prompted for the password, I entered 'infected' to proceed with the extraction.

#

<img width="784" alt="Screenshot 2025-01-19 211335" src="https://github.com/user-attachments/assets/f02b2028-7f0c-4296-a4be-d982bcd4a613" />

#

We use the ls command to list the contents of the unzipped directory. This command displays the files and subdirectories within the specified directory, providing a quick overview of its structure and contents. By running ls, you can verify that the files have been successfully extracted and are accessible for further analysis.

#

<img width="784" alt="Screenshot 2025-01-19 at 9 19 17 PM" src="https://github.com/user-attachments/assets/55093ebf-f5a2-45cc-a09d-8f54f48fc5ca" />

#

To open Wireshark and begin investigating, simply double-click on the icon that looks like a blue shark fin.

#

<img width="783" alt="Screenshot 2025-01-19 at 9 21 14 PM" src="https://github.com/user-attachments/assets/af86557e-e76e-4ba9-900a-b4b5d8ea0847" />

#

Once Wireshark is open, navigate to the directory where the pcap file is stored (~/root/Desktop/ChallengeFile). To do this:

1. Click on the File menu located in the top-left corner of your screen.
2. Select Open from the drop-down menu, or alternatively, press Ctrl+O on your keyboard.

#

<img width="788" alt="Screenshot 2025-01-19 at 9 23 26 PM" src="https://github.com/user-attachments/assets/85fa5de3-961c-4c16-98a4-ca86c9d63bfa" />

#

3. Navigate to the appropriate directory in the pop-up window.
4. Click on the pcap file (BruteForce.pcap) and click Open.

#

<img width="785" alt="Screenshot 2025-01-19 at 9 24 26 PM" src="https://github.com/user-attachments/assets/3868e1e4-cc52-491c-a7d3-c21487f2ec28" />

#

### Question 1. What is the IP address of the server targeted by the attacker's brute-force attack?

#

#### Answer: _51.116.96.181_


To identify the targeted server, we want to look for the IP address with the most network traffic or the highest volume of packets. This indicates the device that is most actively communicating in the capture and is likely the target of the communication or attack. The conversations tab will display details such as the source and destination IPs, packet counts, and data transfer volumes, helping you pinpoint the server being targeted.

We want to following these steps:

1. Click on the **Statistics** tab at the top of the screen.
2. From the drop-down menu, select **Conversations**.

#

<img width="786" alt="Screenshot 2025-01-20 at 10 49 55 AM" src="https://github.com/user-attachments/assets/7fd98eb1-9465-4e21-a74d-9520f0abd125" />

#

From the conversation window, we want to take the following steps:

1. Click on the **IPv4** tab to display the IP addresses of all the endpoints involved in the conversations.
2. Sort the results by **Packets** to easily view the conversations with the highest packet counts and data transfer volumes.
3. Observe the flow of traffic between **Address A** (the source of the traffic) and **Address B** (the destination of the traffic).
4. Pay attention to the byte size of each conversation to identify which endpoint (IP address) is involved in the highest volume of data transfer, helping you pinpoint the server that is most likely targeted by the attack.

#

<img width="783" alt="Screenshot 2025-01-20 at 10 52 56 AM" src="https://github.com/user-attachments/assets/0b5aa646-3e9e-4a97-b02a-171115bf886c" />

#

<img width="781" alt="Screenshot 2025-01-20 at 10 53 47 AM" src="https://github.com/user-attachments/assets/513f62b0-bf73-4d74-ad36-277da443f9a8" />

#

### Question 2. Which directory was targeted by the attacker's brute-force attempt?

#### Answer: _index.php_


Since we are investigating a brute-force attack on our web server, our focus should be on identifying the web service protocols, such as **HTTP** and **HTTPS**, that were used during the attack. These protocols are often used for web traffic and can help identify the targeted directory, including any attempts to break into restricted areas, exploit weaknesses, or overload the server with repeated login attempts.


To filter for HTTP traffic:
1. Click the **filter** bar at the top of the screen.
2. Type '**http**', then press Enter.
This will focus on HTTP traffic and exclude other protocols.

#

<img width="782" alt="Screenshot 2025-01-20 at 10 56 10 AM" src="https://github.com/user-attachments/assets/f0ffa8eb-b9c8-4d2d-9a6d-b060d0a592fc" />

#

In the **Info** column, we see a summary of each packet's content, providing key details about the communication, such as the protocol used, the packet's direction (request or response), and relevant information like HTTP methods, status codes, or other specific data depending on the protocol.

#

<img width="783" alt="Screenshot 2025-01-20 at 10 57 13 AM" src="https://github.com/user-attachments/assets/b2236bca-9a89-45dc-b012-d738664afe86" />

#

To get details about the conversation, we follow the stream. This simplifies the investigation process by providing a comprehensive overview of the communication. This feature is invaluable for network analysis and security investigations, as it allows you to reconstruct and examine the entire conversation between two endpoints, rather than analyzing individual packets separately.

#### Steps:

1. Right-click on any of the packets.
2. Scroll down to the **Follow** option in the drop-down menu.
3. Click on **HTTP Stream** from the menu.

#

<img width="784" alt="Screenshot 2025-01-20 at 10 59 18 AM" src="https://github.com/user-attachments/assets/5318637a-9cb5-4954-a638-a9a957582ad0" />

#

From the HTTP Request header, we can gather valuable information such as the Request Method (e.g., GET, POST), the Host (which identifies the target server IP address), and the User-Agent (which reveals that the request was made using the Requests library in Python, version 2.31.0).

The HTTP request header shows a '**POST /index.php**' request, indicating that the attacker attempted to make a **POST** request to the '**index.php**' file. The reference to the '**index.php**' file suggests that this was the targeted resource in the attacker's brute-force attempt.

#

<img width="785" alt="Screenshot 2025-01-20 at 11 04 02 AM" src="https://github.com/user-attachments/assets/962676cd-ab08-4c22-9a87-6cd591a2570f" />

#

<img width="783" alt="Screenshot 2025-01-20 at 11 04 36 AM" src="https://github.com/user-attachments/assets/7183abc4-0b14-4347-83c4-89f89df09c14" />

#

### Question 3. Identify the correct username and password combination used for login.

#### Answer: _username - web-hacker password admin12345_

To identify the correct username and password, locate HTTP POST requests with login credentials in the request body, typically during authentication. Review the request for parameters like username and password, then check the HTTP response packet for success or failure. Examine the Line-Based Text data field in the Packet Dissection Pane, for authentication details. 

#

<img width="786" alt="Screenshot 2025-01-20 at 11 06 15 AM" src="https://github.com/user-attachments/assets/90db17bb-29d1-4614-8d72-d0f03bcd04d4" />

#

The keyword '**Incorrect**' indicates that the credentials used to authenticate were invalid.

Since the pcap file is very large, we need to apply a string filter to search for packets containing the keyword ‘**Correct**’ in order to identify valid login credentials. To do this, follow these steps:
1. Click on the **magnifying glass** icon at the top of the screen (when you hover over it, it should display '**Find a Packet**').

<img width="787" alt="Screenshot 2025-01-20 at 11 07 43 AM" src="https://github.com/user-attachments/assets/46ca2b86-9eda-4529-acef-5d2dfb088d3f" />

#

2. In the '**Find**' window, change the filter from '**Display Filter**' to '**String**'.

<img width="785" alt="Screenshot 2025-01-20 at 11 08 56 AM" src="https://github.com/user-attachments/assets/093bc77f-085f-40e9-b5c8-fae8ebf09ff5" />

#

3. Switch from '**Packet List**' to '**Packet Details**' to view more specific packet information.

<img width="785" alt="Screenshot 2025-01-20 at 11 09 50 AM" src="https://github.com/user-attachments/assets/6be967d5-ffa1-4115-8981-ec957f8eeade" />

#

4. In the '**Find**' window, enter the keyword '**Correct'** and click Find to search for packets that contain valid credentials.


<img width="784" alt="Screenshot 2025-01-20 at 11 11 55 AM" src="https://github.com/user-attachments/assets/e49f54f1-221c-4943-ad9e-0e6b604c4351" />

#

This will automatically highlight the first packet containing the keyword ‘**Correct**’, indicating that the credentials used for authentication in that packet are valid. To extract the authentication credentials, we need to follow the stream. From the highlighted packet, we can trace the HTTP stream to gather more details. Follow these steps to do so:

1. Right-click on the highlighted packet.
2. Scroll down to the **Follow** option in the drop-down menu.
3. Click on **HTTP Stream** from the menu.

#

<img width="784" alt="Screenshot 2025-01-20 at 11 13 12 AM" src="https://github.com/user-attachments/assets/4c99e1fb-b0f0-4ec8-b769-b20f952cda23" />

#

The request header shows that the username ‘**web-hacker**’ and the password ‘**admin12345**’ were used to successfully authenticate.

<img width="786" alt="Screenshot 2025-01-20 at 11 14 03 AM" src="https://github.com/user-attachments/assets/2e810b98-6b1f-442f-ac14-deb23bd78cd5" />

#

<img width="782" alt="Screenshot 2025-01-20 at 11 14 34 AM" src="https://github.com/user-attachments/assets/efafa915-7689-4b94-9649-7e299d49b123" />

#

### Question 4. How many user accounts did the attacker attempt to compromise via RDP brute-force?

#### Answer: _7_

We first filter the packets to display only traffic that uses the **HTTP POST** method and is directed to the destination IP '**51[.]116[.]96[.]181**', which belongs to the compromised '**web server**'. The HTTP POST method is commonly used to send login credentials to the server during the authentication phase.  

The output shows multiple packets containing information about user accounts the attacker tried using along with password to gain access to the network. 

<img width="785" alt="Screenshot 2025-01-20 at 11 21 07 AM" src="https://github.com/user-attachments/assets/4ce0c92c-1b0f-4402-ae39-406ad530db34" />

<img width="785" alt="Screenshot 2025-01-20 at 11 21 39 AM" src="https://github.com/user-attachments/assets/2d754d63-e4c3-4d6d-ad11-e617d21ae6e7" />

#

To get a count of unique user accounts the attacker attempted to compromise, we first need to save a detailed breakdown of the captured packets as a plain text file for easy access using the command line. Follow these steps:

1. Click File at the top left corner of the screen.
2. Select Export Packet Dissection from the drop-down menu.
3. Click on As Plain Text from the menu provided.

<img width="790" alt="Screenshot 2025-01-20 at 11 22 59 AM" src="https://github.com/user-attachments/assets/69d587f4-04da-4b07-b6c6-1d9d78efe939" />

#

4. Choose the directory where you want to save the file.
5. Name the file (e.g., Brute_force_investigation).
6. Click Save to store the file.

<img width="782" alt="Screenshot 2025-01-20 at 11 24 43 AM" src="https://github.com/user-attachments/assets/1e4ad301-6f82-4a16-ac13-4efd018442b7" />

#

From the **Command Line Interface (CLI)**, navigate to the appropriate directory and list its contents to ensure our file is present.

- ```cd BruteForce``` - Changes to the BruteForce directory.
- ```ls``` - Lists the content(s) of the current directory.

<img width="783" alt="Screenshot 2025-01-20 at 11 25 41 AM" src="https://github.com/user-attachments/assets/7f3c041c-f181-469e-965b-aa6031b70297" />

#

To determine the number of user accounts the attacker attempted to compromise, we need to print the contents of the recently saved text file and extract only the usernames. To do this, run the following command:

```cat Brute_force_investigation.txt | grep -i "username" | uniq | wc -l```

- **cat Brute_force_investigation.txt**: Outputs the contents of the file.
- **| (pipe)**: Passes the output from the previous command to the next command as input.
- **grep -i "username"**: Filters lines containing the word "username," ignoring case sensitivity.
- **| (pipe)**: Passes the filtered lines to the next command as input.
- **uniq**: Removes any duplicate usernames, showing only unique occurrences.
- **| (pipe)**: Passes the unique usernames to the next command as input.
- **wc -l**: Counts the number of unique usernames, providing the total number of user accounts the attacker attempted to compromise.

<img width="779" alt="Screenshot 2025-01-20 at 11 28 14 AM" src="https://github.com/user-attachments/assets/6cac5d6c-1a2f-401c-a6e1-12d17d4e20ab" />

#

<img width="784" alt="Screenshot 2025-01-20 at 11 33 14 AM" src="https://github.com/user-attachments/assets/066fe0d1-2038-408f-b5d8-a3d284ee4cd5" />

#

### Question 5. What is the “clientName” of the attacker's machine?

#### Answer: _t3m0-virtual-ma_

To determine the client name of the attacker's machine, we switch back to Wireshark. Since we are investigating an RDP brute force attack, we will apply a filter to display only RDP traffic, allowing us to focus on relevant packets. The client name information is typically found following the 'Negotiate Response' message. Follow these steps:

1. Click the filter bar at the top of the screen and type '**RDP**', then press Enter.
2. Look for the '**Negotiate Response**' message.
3. Select the packet that follows the '**Negotiated Response**' message.
Expand the **Remote Desktop Protocol** section in the **Packet Dissection Pane**.
Expand the **ClientData** and the **ClientCoreData fields**.
In the **ClientName** field, we will find the client name of the attacker’s machine.

<img width="784" alt="Screenshot 2025-01-20 at 11 37 05 AM" src="https://github.com/user-attachments/assets/8d06a8bc-2260-4c47-9dc9-c557322cd354" />

#

<img width="785" alt="Screenshot 2025-01-20 at 11 37 35 AM" src="https://github.com/user-attachments/assets/0e464fde-76a1-4205-b546-b9a2de1d2fb3" />

#

### Question 6. When did the user last successfully log in via SSH, and who was it?

#### Answer: _mmox:11:43:54_ (username - mmox, time - 11:43:54) 

Both successful and unsuccessful SSH authentication attempts are recorded in the **auth.log** file. From the Command Line Interface (CLI), navigate to the appropriate directory. In the **BruteForce** directory, which contains our investigation files, run the following command:

```cat auth.log | grep -i "Accepted Password"```

- **cat auth.log**: Outputs the contents of auth.log file.
- **| (pipe)**: Passes the output of the previous command as an input to the next command.
- **grep -i “Accepted Password”**: Filters lines containing "Accepted Password” disregarding case sensitivity.

This command will filter and display lines in the auth.log file that contain the phrase '**Accepted Password**', indicating successful SSH authentication attempts.

<img width="783" alt="Screenshot 2025-01-20 at 11 42 23 AM" src="https://github.com/user-attachments/assets/65f9ed0d-7528-40fc-9750-7cb2cb9d38a6" />

From the displayed output, we can see that the last successful SSH login occurred on February 25 at **11:43:54**, and the username used for authentication was **mmox**.

#

<img width="785" alt="Screenshot 2025-01-20 at 11 44 17 AM" src="https://github.com/user-attachments/assets/3463b320-bab6-48a7-8ba1-4917eee7bb6a" />

#

### Question 7. How many unsuccessful SSH connection attempts were made by the attacker?

#### Answer: _7480_

Since the **auth.log** file contains both successful and unsuccessful SSH connection attempts, we will filter the output to display only the unsuccessful attempts and count them. This will help us determine the number of failed login attempts.
From the Command Line Interface (CLI), navigate to the appropriate directory. In the **BruteForce** directory, which contains our investigation files, run the following command:

```grep -i "Failed Password" auth.log | wc -l```

- **grep -i “Failed Password”**: Searches for lines containing the phrase "Failed Password" disregarding case sensitivity.
- **auth.log**: Specifies the file to search within
- **| (pipe)**: Passes the output of the previous command as an input to the next command.
- **wc -l**: Counts the number of lines in the input, providing the total number of unsuccessful SSH connection attempts.

<img width="785" alt="Screenshot 2025-01-20 at 11 47 13 AM" src="https://github.com/user-attachments/assets/83d37a13-94b7-48b9-8b4c-e92b1b197314" />

#

<img width="783" alt="Screenshot 2025-01-20 at 11 47 43 AM" src="https://github.com/user-attachments/assets/fb447c89-7b36-4c86-a07e-c242252bc352" />

#

### Question 8. What technique is used to gain access?

#### Answer: _T1110_


To get the **Mitre ID** for the technique used (Brute Force), we need to visit the **MITRE ATT&CK** webpage and search for **Brute Force**. Follow these steps:

1. Open a web browser and search for the **MITRE ATT&CK** webpage
2. Select **MITRE ATT&CK**

<img width="800" alt="Screenshot 2025-01-20 at 11 49 55 AM" src="https://github.com/user-attachments/assets/fc43c97b-de02-49e5-8792-21ec6f4af7e6" />

#

2. In the search bar, type '**Brute Force**' and press Enter.
3. Review the search results and locate the **Brute Force technique**.

<img width="794" alt="Screenshot 2025-01-20 at 11 51 19 AM" src="https://github.com/user-attachments/assets/174a53a3-a8ec-4bd5-9f9e-c036060a77e8" />

#

Click on the **Brute Force technique** to view more details.
On the technique page, find the **Mitre ID** (e.g., **T1110**) listed at the top of the page.

<img width="789" alt="Screenshot 2025-01-20 at 11 52 53 AM" src="https://github.com/user-attachments/assets/37f9a06b-06d7-41a4-a14d-1af5a10f5819" />

#

<img width="780" alt="Screenshot 2025-01-20 at 11 53 25 AM" src="https://github.com/user-attachments/assets/2e6dfbf8-ad44-4a19-aac3-0aed8a35169a" />

#

