# SOC Automation

## 1. Introduction

### Overview
The **SOC Automation Project** aims to create an automated Security Operations Center (SOC) workflow that streamlines event monitoring, alerting, and incident response. 

By leveraging powerful open-source tools such as:
- **Wazuh**: For comprehensive event management and alerting.
- **Shuffle**: For workflow automation.
- **TheHive**: For case management and coordinated response actions.

This project enhances the efficiency and effectiveness of SOC operations.  

### Key Components:
- **Windows 10 Client**: Configured with **Sysmon** for detailed event generation.
- **Ubuntu Client**: Equipped with the **Wazuh agent** for advanced event collection and analysis.
- **Wazuh Server**: Centralized security monitoring platform.
- **Shuffle**: Automates alert processing and incident workflows.
- **TheHive**: Facilitates case management and structured responses.

  ![image](https://github.com/user-attachments/assets/d518df88-a09b-470c-af7f-52cc5682b74e)

## 2. Purpose and Goals

- **Automate Event Collection and Analysis**  :
  Ensure security events are collected and analyzed in real-time with minimal manual intervention, enabling proactive threat detection and response.

- **Streamline Alerting Process**  :
  Automate the process of generating and forwarding alerts to relevant systems and personnel, reducing response times and minimizing the risk of overlooking critical incidents.

- **Enhance Incident Response Capabilities** : 
  Automate responsive actions to security incidents, improving reaction time, consistency, and effectiveness in mitigating threats.

- **Improve SOC Efficiency**  :
  Reduce the workload on SOC analysts by automating routine tasks, allowing them to focus on high-priority issues and strategic initiatives.

## 3. Prerequisites

### Software Requirements:
- **VirtualBox**: Industry-standard virtualization platform for creating and managing virtual machines.
- **Ubuntu 22.04**: The stable and feature-rich Linux distribution for deploying Ubuntu clients.
- **Cloud Platform**: Access to a cloud platform to host all virtual machines.
- **Windows 10**: The client machine for generating realistic security events and testing the SOC automation workflow.
- **Sysmon**: A powerful Windows system monitoring tool that provides detailed event logging and telemetry.

### Tools and Platforms:
- **Wazuh**: An open-source, enterprise-grade security monitoring platform that serves as the central point for event collection, analysis, and alerting.
- **Shuffle**: A flexible, open-source security automation platform that handles workflow automation for alert processing and response actions.
- **TheHive**: A scalable, open-source Security Incident Response Platform designed for SOCs to efficiently manage and resolve incidents.
- **VirusTotal**: An online service that analyzes files and URLs to detect various types of malicious content using multiple antivirus engines and scanners.
- **Kali Linux**: A powerful, open-source penetration testing platform used to simulate attacks and assess system vulnerabilities.
## 4. Setup
### Install and Configure Windows 10 with Sysmon
- **Download Sysmon**
   
![image](https://github.com/user-attachments/assets/8298c1d8-f745-4969-a337-7397fc3d819c)

- **Install Sysmon**  
   Run the Sysmon installer using powershell with administrative privileges and apply the configuration file that needs to be downloaded seperately to enable detailed event logging.
   
![image](https://github.com/user-attachments/assets/54ff2b79-72cd-474f-8aa8-66d3f66d7379)

 - **Verify Installation**  
   Open the Windows Event Viewer and confirm that Sysmon is logging detailed telemetry data under the "Microsoft-Windows-Sysmon/Operational" log.

### Set Up Wazuh Server
- To set up the Wazuh server, we will be using Azure, a popular cloud service provider. We start by deploying a new virtual machine:

![image](https://github.com/user-attachments/assets/24722f2c-060c-44a3-9155-00aba3fc52f4)

- Connect to the Wazuh Server via SSH 

![image](https://github.com/user-attachments/assets/8bde1fae-32fc-431b-9f38-775c27e12eb5)

- Install Wazuh:
We start the Wazuh installation using the official Wazuh installer script:

![image](https://github.com/user-attachments/assets/c197796b-447f-4cb5-9b98-5edfaecc3c30)

- Access the Wazuh Web Interface:
To log in to the Wazuh web interface, we open a web browser and enter the Wazuh server's public IP address with https:// prefix:

![image](https://github.com/user-attachments/assets/e34cc75e-6731-4b75-bd9a-d0a4d1dfba20)

### Install TheHive
- **Create a New Virtual Machine for TheHive:**  
We deploy another virtual machine on Azure with Ubuntu 22.04 for hosting TheHive.

![image](https://github.com/user-attachments/assets/de2fdc1c-81ac-49b3-9af3-e4ff80058072)

- **Install Dependencies:**
We start by installing the necessary dependencies for TheHive:

![image](https://github.com/user-attachments/assets/a4275ef2-be69-4ed8-86c7-29de013c2c6e)

- **Install java:**

![image](https://github.com/user-attachments/assets/43fb8bde-0673-4c27-a8db-07452a1f1d23)


### Install Cassandra 
Cassandra is the database used by TheHive for storing data.

![image](https://github.com/user-attachments/assets/fa6c6c60-f822-4f65-bbed-d4a928354160)

### Install Elasticsearch
Elasticsearch is used by TheHive for indexing and searching data.

![image](https://github.com/user-attachments/assets/9ffc9d01-ea13-416b-bd60-2f8996574771)

### Install TheHive 

![image](https://github.com/user-attachments/assets/9dbce43d-127b-4bd1-92b1-4016954a5daf)
![image](https://github.com/user-attachments/assets/416fc989-1455-4b54-b241-25210b852b25)
![image](https://github.com/user-attachments/assets/1626c26b-555e-437e-9253-661d61881df4)

- Default credentials for accessing TheHive on port 9000:

![image](https://github.com/user-attachments/assets/97599046-be1f-42f5-abcf-14f90417e93d)

### Configure TheHive and Wazuh
- Configure Cassandra: Cassandra is TheHive's database. We need to configure it by modifying the cassandra.yaml file:
  
![image](https://github.com/user-attachments/assets/a20f3496-ea2c-47d2-8701-43aacb4d1e92)

- Set the listen_address to TheHive's public IP:

![image](https://github.com/user-attachments/assets/ce8fa09a-c631-44c1-bea8-c8f988cebd1c)

- Next, configure the RPC address by entering TheHive's public IP.
- Lastly, change the seed address under the seed_provider section. Enter TheHive's public IP in the seeds field:
  
![image](https://github.com/user-attachments/assets/0b386fec-e1aa-4e9d-8915-6568e027fee9)

- Restart and Check the Cassandra service status to ensure it's running:

![image](https://github.com/user-attachments/assets/2286d51a-3892-425d-aa0e-c65b347ede2e)

### Configure Elasticsearch:
- Elasticsearch is used for data indexing in TheHive. We need to configure it by modifying the elasticsearch.yml file:
  
![image](https://github.com/user-attachments/assets/9e12f44a-ec3b-453f-a27d-37f5ae7d1e36)
![image](https://github.com/user-attachments/assets/0d3d9df2-344d-463c-991c-5697fa70dd88)

- Restart and Check the Elasticsearch service status:

![image](https://github.com/user-attachments/assets/8efc2d6e-44cf-47c2-9615-e677d5119ed9)

### Configure TheHive:
- Before configuring TheHive, ensure the thehive user and group have access to the necessary file paths:
  
![image](https://github.com/user-attachments/assets/390576e8-d091-4b89-8ae0-af4cf4155a81)

- Now, configure TheHive's configuration file:
- Modify the database and index config sections. Change the hostname IP to TheHive's public IP. Set the cluster.name to the same value as the Cassandra cluster name ("SOAR" in this example). Change the index.search.hostname to TheHive's public IP. At the bottom, change the application.baseUrl to TheHive's public IP.

![image](https://github.com/user-attachments/assets/9fe248ff-fb96-4e88-bf76-3d3f93786c89)
![image](https://github.com/user-attachments/assets/ec2fa75e-1683-4a6d-b3af-47e142f979f1)

- Save the file, Restart and check the TheHive service:

![image](https://github.com/user-attachments/assets/60c10f66-aba5-47b8-8125-599102511253)

- If all services are running, access TheHive from a web browser using TheHive's public IP and port 9000:

![image](https://github.com/user-attachments/assets/4d0bdee1-ef36-4d97-8124-7983e1c8cfac)

### Configure Wazuh

![image](https://github.com/user-attachments/assets/c58b4847-2216-4ef4-9137-54a91e0e3bb4)

- Copy the installation command provided and execute it in PowerShell on the Windows client machine. The Wazuh agent installation will start.
- After the installation, start the Wazuh agent service using the net start wazuhsvc command or through Windows Services.

![image](https://github.com/user-attachments/assets/8dc2a4d3-b954-43de-922b-f7f4a058d4c9)

### Verify the Wazuh Agent
- Check the Wazuh web interface to confirm the Windows agent is successfully connected.

![image](https://github.com/user-attachments/assets/c021a6f9-8eb2-47c8-845f-e7ce3fa4282b)

- The Windows agent should be listed with an "Active" status.

![image](https://github.com/user-attachments/assets/1aaf78b2-25b4-43b3-8063-d3f3302b789c)

## Generating Telemetry and Custom Alerts
### Configure Sysmon Event Forwarding to Wazuh
- In the ossec.conf file, add a new <localfile> section to configure Sysmon event forwarding to Wazuh. Check the full name of the Sysmon event log in the Windows Event Viewer.
- Add the following configuration to the ossec.conf file:

![image](https://github.com/user-attachments/assets/60bcaaea-6dbc-4f1b-a73e-e625900a14e3)

- Restart the Wazuh agent service to apply the configuration changes.
### Verify Sysmon Event Forwarding:
- In the Wazuh web interface, go to the "Events" section and search for Sysmon events to confirm they are being received.

![image](https://github.com/user-attachments/assets/7b33eb99-4284-4d75-9516-7ff0563634f6)

### Generate Mimikatz Telemetry
- On the Windows client machine, download Mimikatz, a tool commonly used by attackers and red teamers to extract credentials from memory. To download Mimikatz, you may need to exclude the download directory from scanning.

![image](https://github.com/user-attachments/assets/441aa2d1-836d-41d5-9645-6ba9d10fd72f)

### Execute Mimikatz:
Open PowerShell, navigate to the directory where Mimikatz is downloaded, and execute it.

![image](https://github.com/user-attachments/assets/f2c71fc0-3f36-4678-a077-1faa5d587a9f)

### Configure Wazuh to Log All Events:
- By default, Wazuh only logs events that trigger a rule or alert. To log all events, modify the Wazuh manager's ossec.conf file. open /var/ossec/etc/ossec.conf. Logall and Logalljson should be changed to yes.

![image](https://github.com/user-attachments/assets/2efcfd1a-d98e-46fb-9693-2dbbe31c1e0d)

### Configure Filebeat:
- To enable Wazuh to ingest the archived logs, modify the Filebeat configuration: Archives should be set to true.


![image](https://github.com/user-attachments/assets/d0e64e47-b294-4028-a994-9cb55134fa02)

### Create a New Index in Wazuh:
 
- After updating Filebeat and the Ossec configuration, create a new index in the Wazuh web interface to search the archived logs. From the left-side menu, go to "Stack Management" > "Index Management".

![image](https://github.com/user-attachments/assets/5bdbe69b-f1b7-44dd-94c8-cbaec49a79bb)

- Create a new index named wazuh-archives-* to cover all archived logs.

![image](https://github.com/user-attachments/assets/d927b152-9b10-4d73-98da-1605b10651be)

- On the next page, select "timestamp" as the time field and create the index.
- Go to the "Discover" section from the left-side menu and select the newly created index.

![image](https://github.com/user-attachments/assets/8ffc3ad9-9f4b-48cf-8d8b-3dac5380e1bc)

### Troubleshoot Mimikatz Logs:
- To troubleshoot if Mimikatz logs are being archived, use cat and grep on the archive logs in the Wazuh manager CLI:

![image](https://github.com/user-attachments/assets/3e508ff4-c55e-44c8-9c43-5c76c7e6b521)

### Relaunch Mimikatz:
- Relaunch Mimikatz on the Windows client machine and check the Event Viewer to ensure Sysmon is capturing Mimikatz events.
- Check the archive file again for Mimikatz logs to confirm they are being generated.

![image](https://github.com/user-attachments/assets/5250a860-a53c-4517-a885-329add4da453)
![image](https://github.com/user-attachments/assets/196d62fb-ca1d-4abb-a1b0-c0b277813bcb)
![image](https://github.com/user-attachments/assets/d53ad9b5-de78-4237-aae4-4d8fa3a45c1b)

### Create a Custom Mimikatz Alert
- Let’s create a custom rule either from the CLI or the Wazuh web interface.

![image](https://github.com/user-attachments/assets/3625b2c6-e25d-4fa3-872e-d440bd178f3a)

- In the web interface, click on the "Manage rule files" button. Filter the rules by name ("sysmon") and view the rule details by clicking the eye icon.

![image](https://github.com/user-attachments/assets/4c6bd237-973a-4c06-bec6-4c852e8cf53d)

- These are Sysmon-specific rules built into Wazuh for event ID 1. Copy one of these rules as a reference and modify it to create a custom Mimikatz detection rule.
- Go to the "Custom rules" button and edit the "local_rules.xml" file. Add the custom Mimikatz detection rule.

![image](https://github.com/user-attachments/assets/73718505-7039-4a48-90f2-6b3bef392e71)

- Save the file and restart the Wazuh manager service.

### Test the Custom Rule:
- To test the custom rule, rename the Mimikatz executable on the Windows client machine to something different.

![image](https://github.com/user-attachments/assets/47e01ada-4e70-4c4d-8398-6516b76178f9)

- Execute the renamed Mimikatz.

![image](https://github.com/user-attachments/assets/4a182ba5-2454-4504-80fb-712c98627ad3)

- Verify that the custom rule triggers an alert in Wazuh, even with the renamed Mimikatz executable.

![image](https://github.com/user-attachments/assets/8340ad5a-dfb6-4bfe-b512-58eec90b0f13)

## Automation with Shuffle and TheHive
### Set Up Shuffle
- Create a New Workflow: Click on "New Workflow" and create a workflow. You can select any random use case for demonstration purposes.

![image](https://github.com/user-attachments/assets/e23185e0-73b1-498d-8831-852d371ba65d)
![image](https://github.com/user-attachments/assets/de7b9dfd-b7fc-4d76-9886-5ead255a5655)

### Add a Webhook Trigger:
- On the workflow page, click on "Triggers" at the bottom left. Drag a "Webhook" trigger and connect it to the "Change Me" node. Set a name for the webhook and copy the Webhook URI from the right side. This URI will be added to the Ossec configuration on the Wazuh manager.

![image](https://github.com/user-attachments/assets/692bafef-8ec6-401c-b173-a2f275ee2d67)

- Configure	Wazuh	to	Connect	to	Shuffle: On	the	Wazuh	manager	CLI,	modify the ossec.conf file to add an integration for Shuffle:

![image](https://github.com/user-attachments/assets/57d1715a-498b-4d65-8a38-a1e2495f5738)

- Restart the Wazuh manager service

### Execute the malware:

![image](https://github.com/user-attachments/assets/3e2bbbfe-c9cf-4ceb-814a-d90659ed372f)

### Test the Shuffle Integration:

- Regenerate the Mimikatz telemetry on the Windows client machine. In Shuffle, click on the webhook trigger ("Wazuh-Alerts") and click "Start".

![image](https://github.com/user-attachments/assets/91221100-b053-4f0a-b4fe-715af17d190e)

## Build a Mimikatz Workflow 
### Workflow Steps:

1.	Mimikatz alert sent to Shuffle
2.	Shuffle receives Mimikatz alert / extract SHA256 hash from file
3.	Check reputation score with VirusTotal
4.	Send details to TheHive to create an alert
5.	Send an email to the SOC analyst to begin the investigation

### Extract SHA256 Hash:
- Observe that the return values for the hashes are appended by their hash type (sha1=hashvalue). To automate the workflow, parse out the hash value itself. Sending the entire value, including sha1= to VirusTotal will result in an invalid query.
- Click on the "Change Me" node and select "Regex capture group" instead of "Repeat back to me". In the "Input data", select the "hashes" option. In the "Regex" tab, enter the regex pattern to parse the SHA256 hash value: SHA256=([0-9A-Fa-f]{64}). Save the workflow.

![image](https://github.com/user-attachments/assets/1d78417c-f4c9-46e7-9a70-81b6f2ab3fcb)

- Click on the "Show execution" button (running man icon) to verify that the hash value is extracted correctly.

![image](https://github.com/user-attachments/assets/427236f3-7e95-4f86-8504-ec928c012aa8)

### Integrate VirusTotal:
- Create a VirusTotal account to access the API.
- Copy the API key and return to Shuffle. In Shuffle, click on the "Apps" tab and search for "VirusTotal". Drag the "VirusTotal" app to the workflow, and it will automatically connect.

![image](https://github.com/user-attachments/assets/3c59b0a5-84e8-44e8-aa28-9b9ab75570ec)

- Enter the API key on the right side or click "Authenticate VirusTotal v3" to authenticate.

![image](https://github.com/user-attachments/assets/d2af56a1-4588-4ce8-a3cd-fa5d45770ad2)

- Change the "ID" field to the "SHA256Regex" value created earlier.
- Expand the results to view the VirusTotal scan details, including the number of detections.

![image](https://github.com/user-attachments/assets/cf539f4e-2ec7-4fa6-aa6e-9e6157c5c88c)

- Under "Find actions", click on "TheHive" and select "Create alerts". Set the JSON payload for TheHive to receive the alerts.

![image](https://github.com/user-attachments/assets/c72e5a56-2abc-4572-abe0-a5a477018a09)

- Save the workflow and rerun it. An alert should appear in the TheHive dashboard.

![image](https://github.com/user-attachments/assets/9726c4d2-9802-460f-986f-25549d2effb4)

- Click on the alert to view the details.

![image](https://github.com/user-attachments/assets/704297d5-b52a-4e6f-b4ce-88890a694b9c)

### Send Email Notification:
- In Shuffle, find "Email" in the "Apps" and connect VirusTotal to the email node.

![image](https://github.com/user-attachments/assets/3cd60766-0da9-4758-9067-1794f2c76ac9)

- Verify that the email is received with the expected alert details.

![image](https://github.com/user-attachments/assets/4e34d85b-1f1d-410d-ac8a-bc9dee8098e0)

## SSH Brute Force Attack Automation with Shuffle :
### Build a SSH brute force response Workflow :

Workflow Steps:
1.	Ssh brute force alert sent to Shuffle
2.	Shuffle receives ssh brute force alert / extract source ip address from file
3.	Get nan ip report with VirusTotal
4.	Send commands to wazuh to trigger the auto-response
5.	Send an email to the SOC analyst to begin the investigation
- First let’s add another agent (ubuntu machine) that will be our test subject

![image](https://github.com/user-attachments/assets/7bdac402-a515-4259-8b54-a6565acaf041)

- second let’s try to trigger the alert related to ssh brute force on wazuh by using a well know tool HYDRA to emulate an ssh brute force attack on the ubuntu machine:

![image](https://github.com/user-attachments/assets/de808dad-0a17-4a56-8310-f49feb64f381)

- Check wazuh to see if there are any authentication failure logs or ssh brute force attack alerts generated:

![image](https://github.com/user-attachments/assets/57c335c7-50a1-4f80-95e8-4ad0af1aa878)

- this dashboard indicates more than 80 authentication failures attempt on the ubuntu machine. And the alert has been generated successfully

![image](https://github.com/user-attachments/assets/c6c9c8de-4753-4936-b1bd-1e16eb543453)

- Now let’s continue with our shuffle workflow. Let’s send the alert to shuffle.
- Let’s start by modifying the ossec.conf file to specify the alert to be send to shuffle:

![image](https://github.com/user-attachments/assets/0e91db13-b095-45db-ae1f-0de427248dd4)

- Run the workflow and we should see the alert popped up in shuffle:

![image](https://github.com/user-attachments/assets/4f906a40-44be-413d-bd45-97c07dc12239)

- Retrieve the HTTP application and modify its parameters to use curl and the appropriate URL in order to obtain the JSON Web Token (JWT), which will later be used to connect to Wazuh.

![image](https://github.com/user-attachments/assets/849d24aa-9f1c-42cc-b5cd-a727b6097b31)

- Connect virustotal to the workflow and change its parameter action  get an ip report and ip
- specify source ip address from the available fields.

![image](https://github.com/user-attachments/assets/0cb89d24-6801-478a-9638-c451041db712)

- Test the workflow:

![image](https://github.com/user-attachments/assets/1b014f24-9020-4925-90b1-173e76d6a92f)

- Integrate Wazuh into the workflow by adding the Wazuh application. Configure it to retrieve the web token from the GET API we added earlier, and update the URL accordingly.

![image](https://github.com/user-attachments/assets/8f1e55af-3044-4ac4-8a60-e7ae74f642d0)

- Before proceeding with the workflow, we need to add active response commands to the Wazuh server to block the malicious IP addresses attempting to brute force the server. To do this, modify the file /var/ossec/etc/ossec.conf and add the following lines:

![image](https://github.com/user-attachments/assets/0bdbedea-f1ff-48da-a1a3-67a5c480f312)

- Test the active response by attempting to block the agent from connecting to the internet. Use the agent_control tool located in /var/ossec/bin/agent_control with the following command:

![image](https://github.com/user-attachments/assets/658c5b3f-0562-4eb5-bf19-cd97eef60f53)

- To confirm if the command works, head to the Ubuntu machine and try to ping 8.8.8.8. Then, check the iptables rules with the following command :

![image](https://github.com/user-attachments/assets/7a7dd8d0-f67f-41ae-8294-85ec21c7a4c0)

- The active response is successfully working.
- Now let’s specify what we did in our shuffle workflow by modifying wazuh app parameters: 
  - Command --> firewall-drop0
  - Agent --> specify the agent id field
  - Alerts --> specify the source ip to be blocked

![image](https://github.com/user-attachments/assets/183a8ba8-6055-44a4-a026-33ebba1719e6)

- Execute our workflow:

![image](https://github.com/user-attachments/assets/d40843df-1ee3-4d10-b0fa-e20b3b626f79)

- The workflow is working. Let's further verify it by going to the Wazuh web application to check the generated logs.

![image](https://github.com/user-attachments/assets/4ffaa523-1bd8-4e2e-95ce-ff363fc34e15)
![image](https://github.com/user-attachments/assets/d545ec12-296c-4101-9aa2-d222be7df58a)

- Finally, Add the email application in order to notify the SOC analyst.

![image](https://github.com/user-attachments/assets/449bf6e6-9a48-44f8-ae2d-3ebc87345ff2)

- Execute the workflow :

![image](https://github.com/user-attachments/assets/e5b38479-6810-4f47-aa8f-8b991eaaa19c)

- Email sent successfully.

![image](https://github.com/user-attachments/assets/6e95d46d-8d47-40b7-bdc4-d5bb1c35d5f1)


































