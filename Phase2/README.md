# Phase 2: SIEM Dashboard Analysis

## SIEM Implementation

For our Security Information and Event Management (SIEM) solution, we selected **Splunk** due to its robust log collection capabilities, visualization tools, and extensive search functionality.

### Splunk Setup

#### Splunk Installation
- Installed Splunk Enterprise on a dedicated VM
- Configured Splunk with default ports and network settings
- Created dedicated indexes for both victim and attacker logs

#### Log Collection Configuration

1. **Victim Environment (Metasploitable3)**
   - Installed Splunk Universal Forwarder on the victim machine
   - Configured forwarder to collect authentication logs (`/var/log/auth.log`)
   - Set up secure connection between forwarder and Splunk server

2. **Attacker Environment (Kali Linux)**
   - Configured logging for attack tools
   - Collected system logs related to outbound connections

### Forwarder Configuration

We configured the Splunk Universal Forwarder on the Metasploitable3 machine to collect relevant logs:

```bash
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log
```

We verified the active forwarders using:

```bash
sudo /opt/splunkforwarder/bin/splunk list forward-server
```

![Splunk Forwarder Configuration](https://github.com/Jaijer/Security_Project/blob/main/Phase2/img3.jpeg?raw=true)

As shown in the screenshot, we successfully configured the forwarder to communicate with our Splunk server on 192.168.56.103:9997.

## Log Analysis and Visualization

### Event Timeline Analysis

After collecting logs from both environments, we created visualizations to analyze the attack patterns:

![Splunk Dashboard](https://github.com/Jaijer/Security_Project/blob/main/Phase2/img4.jpeg?raw=true)

The dashboard shows:
- A timeline of events from the victim machine
- Authentication events and session information
- Command executions during the attack period
- Source and destination information for connections

### Key Findings from Log Analysis

1. **Attack Pattern Detection**
   - We observed clear patterns in the logs showing the ProFTPD exploitation
   - Authentication logs showed anonymous login attempts
   - Commands executed on the system were captured in auth.log

2. **Timeline of Events**
   - The logs show the attack progression from initial connection to command execution
   - We identified specific timestamps when the attacker gained shell access
   - Multiple session openings and closings were detected, indicating command execution

3. **User Activity Analysis**
   - The logs show activity under both root and vagrant users
   - Commands were executed with escalated privileges
   - Session information shows the duration of attacker presence on the system

4. **Critical Events Identified**
   - 11:05:24 PM: Multiple session closures for root user
   - 11:05:21 PM: User sessions opened by vagrant
   - 11:05:20 PM: Splunk monitor commands executed
   - Various commands related to the Splunk forwarder were executed

### Forensic Value of SIEM Data

The SIEM dashboard provided valuable forensic information that would be critical in a real-world incident response scenario:

1. **Attack Attribution**
   - Source IP addresses were clearly identified
   - Connection patterns showed the attack origin

2. **Impact Assessment**
   - Commands executed by the attacker were captured
   - System resources accessed were logged

3. **Timeline Reconstruction**
   - The entire attack sequence could be reconstructed
   - Duration of attacker presence was measurable

## Indicators of Compromise (IoCs)

Based on our SIEM analysis, we identified the following Indicators of Compromise:

1. **Network Indicators**
   - Connections from 192.168.56.102 to ProFTPD on 192.168.56.104
   - Reverse shell connections back to the attacker IP

2. **Host Indicators**
   - Creation of unauthorized files in /var/www/html
   - Execution of Python commands for reverse shell
   - Anonymous FTP login attempts

3. **Log Indicators**
   - SITE CPFR and SITE CPTO commands in FTP logs
   - Unexpected session openings in auth logs
   - Commands executed by non-standard users

## Conclusion

The SIEM analysis provided comprehensive visibility into the attack lifecycle, from initial exploitation to command execution. The Splunk dashboard effectively visualized the attack patterns and provided valuable forensic data that would be essential for incident response.

In Phase 3, we will develop and implement defense mechanisms to mitigate this vulnerability and prevent similar attacks in the future.
