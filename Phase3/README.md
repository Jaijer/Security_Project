# Phase 3: Defensive Strategy Proposal

## Vulnerability Recap

Before implementing our defensive strategy, let's recap the vulnerability we exploited:

The **ProFTPD mod_copy module vulnerability (CVE-2015-3306)** allows remote attackers to:
- Read and write files to arbitrary locations on the system
- Execute commands via the SITE CPFR and SITE CPTO commands
- Operate without authentication
- Create backdoors and gain shell access

This vulnerability poses a significant security risk as it allows complete system compromise with minimal effort.

## Defense Strategy

We implemented a multi-layered defense approach to address the ProFTPD vulnerability:

### 1. Patch Management

The most effective solution is to update ProFTPD to a non-vulnerable version. We applied the following updates:

```bash
# Update package lists
sudo apt update

# Install latest ProFTPD version
sudo apt install proftpd -y

# Verify version
proftpd --version
```

### 2. Module Disablement

Since the vulnerability exists specifically in the mod_copy module, we disabled this module:

```bash
# Edit ProFTPD configuration
sudo nano /etc/proftpd/proftpd.conf

# Comment out or remove the mod_copy module
# LoadModule mod_copy.c

# Restart ProFTPD
sudo systemctl restart proftpd
```

### 3. Configuration Hardening

We implemented several configuration changes to enhance ProFTPD security:

```bash
# Edit ProFTPD configuration
sudo nano /etc/proftpd/proftpd.conf

# Add the following security configurations
DefaultRoot ~
RequireValidShell on
AuthOrder mod_auth_file.c
AllowOverwrite off
<Limit SITE_CHMOD SITE_CPFR SITE_CPTO>
  DenyAll
</Limit>
```

These configuration changes:
- Restrict users to their home directories
- Require valid shell access for login
- Deny access to dangerous SITE commands
- Prevent file overwriting

### 4. Authentication Requirements

We enforced strict authentication requirements:

```bash
# Edit ProFTPD configuration
sudo nano /etc/proftpd/proftpd.conf

# Add authentication requirements
IdentLookups off
<Anonymous ~ftp>
  User ftp
  Group nogroup
  UserAlias anonymous ftp
  DirFakeUser on ftp
  DirFakeGroup on ftp
  RequireValidShell off
  <Limit WRITE SITE_CHMOD SITE_CPFR SITE_CPTO>
    DenyAll
  </Limit>
</Anonymous>
```

These changes:
- Disable anonymous write access
- Prevent anonymous users from using dangerous commands
- Maintain read-only functionality for legitimate anonymous users

### 5. Firewall Implementation

We implemented firewall rules to restrict access to the FTP service:

```bash
# Allow FTP only from trusted networks
sudo ufw allow from 192.168.56.0/24 to any port 21

# Enable the firewall
sudo ufw enable
```

### 6. File System Permissions

We adjusted file system permissions to prevent unauthorized access:

```bash
# Set appropriate permissions on web directories
sudo chmod 755 /var/www/html
sudo chown www-data:www-data /var/www/html
```

## Defense Testing and Validation

After implementing our defensive measures, we retested the vulnerability to verify our mitigation was successful.

### Before Defense Implementation

As shown in Phase 1, we were able to:
- Connect to the ProFTPD server anonymously
- Execute SITE CPFR and SITE CPTO commands
- Create a malicious file in the web directory
- Gain shell access to the system

### After Defense Implementation

After applying our defensive measures:

1. **Attempt to use SITE commands:**
   - The SITE CPFR and SITE CPTO commands were blocked
   - Server returned "550 SITE CPFR/CPTO command denied" errors

2. **Attempt to place files in web directories:**
   - File creation attempts were rejected
   - Permission denied errors were returned

3. **Attempt to execute the original exploit:**
   - Both Metasploit module and custom script failed
   - No shell access was gained

### Validation Evidence

We verified our defenses using both Metasploit and our custom script:
### Before:
![Metasploit Exploitation](https://github.com/Jaijer/Security_Project/blob/main/Phase1/img1.jpeg?raw=true)

### After:
![Metasploit Exploitation](https://github.com/Jaijer/Security_Project/blob/main/Phase3/img5.jpeg?raw=true)

The logs from our SIEM platform also confirmed that the attack attempts were unsuccessful, with appropriate error messages being returned to the attacker.

## Security Improvement Analysis

Our defensive strategy significantly improved the security posture of the ProFTPD service:

1. **Vulnerability Elimination:**
   - The specific mod_copy vulnerability was completely mitigated
   - No file operations could be performed without authentication

2. **Defense in Depth:**
   - Multiple layers of protection were implemented
   - Even if one measure failed, others would prevent exploitation

3. **Minimal Service Impact:**
   - Legitimate FTP functionality remained intact
   - Anonymous users could still access allowed resources


## Conclusion

Our defensive strategy successfully mitigated the ProFTPD mod_copy vulnerability through a combination of patching, configuration hardening, and access controls. The multi-layered approach ensured that even if one defensive measure failed, others would prevent successful exploitation.

The before-and-after testing confirmed the effectiveness of our defenses, demonstrating that security can be significantly improved through proper configuration and patching without necessarily replacing the vulnerable service entirely.
