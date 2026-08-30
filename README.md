# wazuh-siem-home-lab- RDP Brute Forece Detection

 ## Project Overview

This project is a complete hands-on SOC Analyst home lab using **Wazuh SIEM**.  

I deployed a Wazuh manager on a Contabo VPS, installed the Wazuh agent and Sysmon on a Windows endpoint, and simulated a real-world **RDP brute-force attack** from a Kali Linux virtual machine. The goal was to detect the attack in real time using Wazuh and analyze the generated alerts.

This lab demonstrates practical skills in:
- SIEM deployment and configuration
- Endpoint monitoring (Windows + Sysmon)
- Attack simulation
- Detection engineering
- Log analysis

---

## Lab Architecture

| Component | Details |
|------------------------|--------------------------------------|
| **SIEM Manager** | Wazuh on Ubuntu (Contabo VPS) |
| **Monitored Endpoint** | Windows 10/11 (Personal PC) |
| **Agent** | Wazuh Agent + Sysmon |
| **Attacker Machine** | Kali Linux VM |
| **Attack Simulated** | RDP Brute Force |

---

## Tools Used

- **Wazuh** (Manager + Agent)
- **Sysmon** (SwiftOnSecurity configuration)
- **Kali Linux**
- **Contabo VPS**
- **Hydra /** (for brute force)
- **Windows RDP**

---

## Setup Summary

### 1. Wazuh Manager (Contabo VPS)
- Deployed Ubuntu server on Contabo
- Installed Wazuh manager, indexer, and dashboard
- Configured firewall (ports 1514, 1515, 443, 55000)

### 2. Windows Endpoint
- Installed Wazuh agent
- Configured agent to point to Contabo public IP
- Installed **Sysmon** with SwiftOnSecurity configuration
- Configured Wazuh agent to collect Sysmon logs (`Microsoft-Windows-Sysmon/Operational`)

### 3. Verification
- Agent showed as **Active** in Wazuh Dashboard
- Windows Security logs and Sysmon events successfully ingested

---

## Attack Simulation

### Objective
Simulate an attacker performing a brute-force attack against Windows Remote Desktop Protocol (RDP) using a weak password.

### Steps Performed
1. Enabled RDP on the Windows endpoint
2. Created a weak password for testing
3. From Kali Linux VM, launched a brute-force attack against the Windows RDP service
4. Successfully gained access to the Windows machine

### Tools Used for Attack
- Hydra / Crowbar
- Custom username/password list containing the weak password

---

## Detection in Wazuh

After the attack, the following was observed in the Wazuh Dashboard:

### Key Alerts
- Multiple failed authentication attempts (Windows Event ID 4625)
- Successful logon after brute force (Event ID 4624)
- Related Sysmon events (process creation, network connections)

### Useful Filters Used
```kql
agent.name: "DESKTOP-SI9234F" and data.win.system.eventID: 4625
data.win.system.eventID: 4624
data.win.system.providerName: "Microsoft-Windows-Sysmon"
```
## Screenshots

![Wazuh Dashboard – Agent Active](images/)  
- Sysmon events in Discover / Threat Hunting  
- Failed RDP logon alerts (Event ID 4625)  
- Successful RDP logon after brute force  
- Kali Linux attack terminal  

---

## Challenges Faced & Solutions

| Challenge                          | Solution                                              |
|------------------------------------|-------------------------------------------------------|
| Agent showing as Stopped           | Fixed `ossec.conf` (invalid manager IP)               |
| Sysmon events not appearing        | Enabled archives in Filebeat + correct `localfile` configuration |
| Agent connection issues            | Re-registered agent and cleaned duplicate entries     |
| Large Sysmon messages dropped      | Increased `queue_size` and `max_size` in manager config |

---

## Lessons Learned

- Proper agent configuration and Sysmon integration are critical for rich telemetry.
- Default Wazuh rules can detect RDP brute force, but custom rules can improve detection quality.
- Enabling archives helps with visibility during lab environments.
- Network connectivity and firewall rules on the VPS must be carefully managed.
- Documenting every step (including troubleshooting) is extremely valuable for learning.

---

## Recommendations (Defensive)

- Disable RDP if not needed, or restrict it by IP.
- Enforce strong passwords + account lockout policies.
- Enable Network Level Authentication (NLA).
- Monitor Event ID 4625 aggressively.
- Use fail2ban or similar solutions on exposed services.
- Deploy Sysmon on all Windows endpoints in a real environment.

---

## Future Improvements

- Create custom Wazuh rules for RDP brute force.
- Add more endpoints (Linux + Windows).
- Simulate additional attacks (pass-the-hash, lateral movement, malware execution).
- Integrate VirusTotal.
- Build dashboards specific to authentication attacks.
- Write detection rules mapped to MITRE ATT&CK.

---

## Author

**Alli Olamide Joshua**  
Aspiring SOC Analyst  

- GitHub: [Cybernerd-josh](https://github.com/Cybernerd-josh)  
- LinkedIn: [LinkedIn](https://www.linkedin.com/in/) *(update with your actual profile link




