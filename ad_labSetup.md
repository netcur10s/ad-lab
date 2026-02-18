# Active Directory Lab Setup — Domain Controller, Windows 11 Endpoints & NTLM Relay

## Overview

This write-up documents the setup of a fully functional Active Directory home lab 
using Proxmox as the virtualization platform. The lab consists of a Windows Server 
domain controller, two Windows 11 workstations joined to the domain, and a 
deliberately vulnerable configuration to practice NTLM relay attack detection 
and mitigation.

## Lab Architecture

| Machine | OS | Role | IP |
|---------|-----|------|----|
| DC01 | Windows Server 2019/2022 | Domain Controller | 192.168.1.10 |
| WS01 | Windows 11 | Domain Workstation (standard) | 192.168.1.20 |
| WS02 | Windows 11 | Domain Workstation (vulnerable) | 192.168.1.30 |
| Attacker | Parrot OS / Kali | Attack Machine | 192.168.1.50 |

## Part 1 — Proxmox Setup

### Creating the Virtual Network

Before spinning up any VMs, create an isolated network in Proxmox so all lab 
traffic stays contained and doesn't touch your home network.

1. Log into the Proxmox web interface
2. Navigate to **Datacenter → Your Node → Network**
3. Click **Create → Linux Bridge**
4. Name it `vmbr1` and leave it without a gateway (isolated network)
5. Apply the changes

All lab VMs will be assigned to `vmbr1`. Your attacker machine can have a second 
NIC on your main bridge (`vmbr0`) for internet access if needed.

### Uploading ISO Files

1. Navigate to **Datacenter → Storage → local → ISO Images**
2. Upload your Windows Server ISO and Windows 11 ISO
3. Also upload your Parrot OS / Kali ISO for the attacker machine

## Part 2 — Setting Up the Domain Controller

### Creating the VM in Proxmox

1. Click **Create VM** in the top right
2. Configure as follows:

| Setting | Value |
|---------|-------|
| Name | DC01 |
| ISO | Windows Server 2022 |
| CPU | 2 cores |
| RAM | 4096 MB |
| Disk | 60 GB |
| Network | vmbr1 |

3. Complete the wizard and start the VM
4. Install Windows Server — select **Desktop Experience** for the GUI

### Configuring a Static IP

After installation, open **Network & Internet Settings** and set a static IP:
```
IP Address:     192.168.1.10
Subnet Mask:    255.255.255.0
Default Gateway: 192.168.1.1
DNS:            127.0.0.1
```

### Installing Active Directory Domain Services

Open PowerShell as Administrator and run:
```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

### Promoting to Domain Controller
```powershell
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetbiosName "LAB" `
  -InstallDns:$true `
  -Force:$true
```

The server will restart automatically. After rebooting, log in as 
`LAB\Administrator`.

### Creating Domain Users
```powershell
# Create a standard user
New-ADUser -Name "John Smith" `
  -GivenName "John" `
  -Surname "Smith" `
  -SamAccountName "jsmith" `
  -UserPrincipalName "jsmith@lab.local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true

# Create a second user for WS02
New-ADUser -Name "Jane Doe" `
  -GivenName "Jane" `
  -Surname "Doe" `
  -SamAccountName "jdoe" `
  -UserPrincipalName "jdoe@lab.local" `
  -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
  -Enabled $true
```

## Part 3 — Setting Up Windows 11 Workstations

### Creating the VMs in Proxmox

Repeat the VM creation process twice with these settings:

| Setting | WS01 | WS02 |
|---------|------|------|
| Name | WS01 | WS02 |
| ISO | Windows 11 | Windows 11 |
| CPU | 2 cores | 2 cores |
| RAM | 4096 MB | 4096 MB |
| Disk | 50 GB | 50 GB |
| Network | vmbr1 | vmbr1 |

> **Note:** Windows 11 requires TPM 2.0. In Proxmox, enable this under 
> the VM's hardware settings by adding a TPM state device and setting 
> the machine type to q35.

### Setting Static IPs

Set WS01 to `192.168.1.20` and WS02 to `192.168.1.30`, with DNS pointing 
to the domain controller at `192.168.1.10`.

### Joining the Domain

On each workstation, open PowerShell as Administrator:
```powershell
Add-Computer -DomainName "lab.local" -Credential LAB\Administrator -Restart
```

After the restart, log in with your domain user credentials to confirm 
the machines are joined successfully.

## Part 4 — Making WS02 Vulnerable to NTLM Relay

NTLM relay attacks work by intercepting authentication requests and 
relaying them to another target on the network. For this to succeed, 
SMB signing must be disabled on the target machine — which is the 
default on workstations but not on domain controllers.

### Disabling SMB Signing on WS02

On WS02, open PowerShell as Administrator:
```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
```

### Disabling Windows Defender and Firewall (Lab Only)

To allow the attack to work cleanly in a lab environment:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

> ⚠️ **These changes make WS02 intentionally insecure. 
> Never apply these settings outside of an isolated lab environment.**
