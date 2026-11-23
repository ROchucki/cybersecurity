# Nmap — Network Scanner

> Module: network scanning & discovery
> Status: in progress

## Purpose

Nmap (Network Mapper) is the standard open-source tool for discovering hosts, open ports, and services on a network. First tool to learn in offensive security and network auditing.

## How it works

1. **Host discovery** — sends packets (ICMP, ARP, TCP SYN) to see which devices respond.
2. **Port scanning** — tries to connect to ports to classify them as open / closed / filtered.
3. **Service & version detection** (`-sV`) — guesses what runs behind a port (e.g. Apache 2.4).
4. **OS detection** (`-O`) — TCP/IP fingerprinting reveals the target operating system.
5. **NSE scripts** (`--script`) — Lua scripts for vulnerability detection, brute force, enumeration.

## Commands by task

### Find live hosts in a network
```bash
nmap -sn 192.168.1.0/24
```

### See what runs on a host (my daily driver)
```bash
nmap -sC -sV <target>
```

### Full TCP port scan
```bash
nmap -sT -p- <target>
```

### Detect operating system
```bash
nmap -O <target>
```

### Check for known vulnerabilities
```bash
nmap --script vuln <target>
```

### Aggressive scan (everything at once, noisy)
```bash
nmap -A <target>
```

### Useful flags cheat list

| Flag | Meaning |
|---|---|
| `-sn` | ping sweep only, no port scan |
| `-sV` | detect service versions |
| `-sC` | run default NSE scripts |
| `-O` | OS detection |
| `-p-` | all 65535 ports |
| `-T4` | faster timing (T0 slowest – T5 fastest/noisiest) |
| `-Pn` | skip host discovery (assume host is up) |
| `-oN file.txt` | save output to file |

## Lab notes

> Add your own observations here after practice sessions (TryHackMe, HackTheBox, local VMs).

- [ ] Example: `-T4` on VMware NAT sometimes misses hosts — verify with slower scan.
- [ ] Example: `-sV` correctly detected vsftpd 2.3.4 on Metasploitable.

## Legal notes

- Scan only systems you own or lab targets with permission.
- Unauthorized scanning is illegal (Poland: art. 267 of the Criminal Code).
- Never commit real third-party scan results to this repository.
