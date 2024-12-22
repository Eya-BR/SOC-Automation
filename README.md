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

