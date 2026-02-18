# 🏢 Active Directory Lab

A hands-on lab environment built to explore Active Directory attack paths, 
defensive configurations, and enterprise security concepts relevant to SOC 
and blue team roles.

---

## 📋 About This Repo

This repo documents my Active Directory home lab — including setup, 
attack simulations, and defensive analysis. Each exercise covers both 
the offensive technique and the defensive detection or mitigation strategy, 
reflecting the dual awareness required in SOC work.

---

## 📂 Exercises

| Exercise | Category | Tools Used | Difficulty |
|----------|----------|------------|------------|
| [AD Lab Setup](./setup) | Environment Build | VirtualBox / Proxmox | Beginner |

*More exercises added as the lab grows.*

---

## 🛠️ Lab Environment

- **Domain Controller:** Windows Server 2019/2022
- **Workstations:** Windows 10/11
- **Attacker Machine:** Parrot OS / Kali Linux
- **Virtualization:** Proxmox
- **Tools:** BloodHound, Mimikatz, Impacket, Nmap, Wireshark

---

## 📂 Topics Covered

| Topic | Description |
|-------|-------------|
| Authentication & Kerberos | Understanding authentication flow and attack vectors |
| Privilege Escalation | Techniques for moving from user to admin |
| Lateral Movement | Methods for pivoting across domain-joined machines |
| Detection & Hardening | Log analysis and configurations to detect AD attacks |

---

## 🎯 Goals

- Understand how enterprise Active Directory environments are structured
- Simulate common attack techniques (Kerberoasting, Pass-the-Hash, etc.)
- Analyze the logs and artifacts each attack generates
- Build detection logic for SOC-relevant AD threats

---

## 📫 Connect

- **LinkedIn:** [linkedin.com/in/vic1101](https://linkedin.com/in/vic1101)
- **Email:** v.echevarria@proton.me
