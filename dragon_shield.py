#!/usr/bin/env python3
"""
DragonShield v2 - Linux System Security Panel
Enhanced with Local/Remote LLM support (Ollama, OpenAI-compatible, Custom endpoints)
"""

import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

import httpx
from rich.markdown import Markdown
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer, Center
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Footer,
    Input,
    Label,
    ListItem,
    ListView,
    OptionList,
    Static,
    TextArea,
    Rule,
    RadioButton,
    RadioSet,
    Select,
)
from textual.widgets.option_list import Option

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG_PATH = Path.home() / ".config" / "dragonshield" / "config.json"


class LLMProvider(str, Enum):
    OPENROUTER = "openrouter"
    OLLAMA = "ollama"
    OPENAI_COMPATIBLE = "openai_compatible"
    CUSTOM = "custom"


DEFAULT_CONFIG = {
    # LLM Provider Settings
    "llm_provider": LLMProvider.OPENROUTER.value,
    "api_key": "",
    "model": "anthropic/claude-3.5-sonnet",
    
    # Provider-specific settings
    "openrouter_base_url": "https://openrouter.ai/api/v1",
    "ollama_base_url": "http://localhost:11434",
    "ollama_model": "llama3.1:8b",
    "openai_base_url": "http://localhost:1234/v1",
    "openai_model": "local-model",
    "custom_base_url": "http://localhost:8080",
    "custom_model": "model",
    "custom_api_key": "",
    
    # General settings
    "max_iterations": 10,
    "command_timeout": 60,
    "auto_fix": False,
    "temperature": 0.2,
    "max_tokens": 4096,
    
    # Exclusions
    "excluded_paths": [
        "/mnt/c", "/mnt/d", "/mnt/e", "/mnt/f",
        "/mnt/wsl", "/proc", "/sys", "/dev",
    ],
    "redacted_patterns": [
        r".*\.pem$", r".*\.key$", r".*id_rsa.*", r".*id_ed25519.*",
        r".*\.env$", r".*password.*", r".*secret.*", r".*token.*",
        r".*\.ssh/.*", r".*/\.gnupg/.*",
    ],
    "dangerous_commands": [
        "rm -rf /", "rm -rf /*", "mkfs", "dd if=", ":(){:|:&};:",
        "> /dev/sda", "chmod -R 777 /", "wget.*|.*sh", "curl.*|.*sh",
    ],
}

AVAILABLE_MODELS = {
    LLMProvider.OPENROUTER: [
        "mistralai/devstral-2512:free",
        "anthropic/claude-3.5-sonnet",
        "anthropic/claude-3-haiku",
        "openai/gpt-4o",
        "openai/gpt-4o-mini",
        "google/gemini-pro-1.5",
        "google/gemini-flash-1.5",
        "meta-llama/llama-3.1-70b-instruct",
        "mistralai/mistral-large",
        "deepseek/deepseek-chat",
    ],
    LLMProvider.OLLAMA: [
        "llama3.1:8b",
        "llama3.1:70b",
        "llama3.2:3b",
        "mistral:7b",
        "mixtral:8x7b",
        "codellama:34b",
        "qwen2.5:14b",
        "deepseek-coder-v2:16b",
        "gemma2:27b",
        "phi3:14b",
    ],
    LLMProvider.OPENAI_COMPATIBLE: [
        "local-model",
        "gpt-4",
        "gpt-3.5-turbo",
    ],
    LLMProvider.CUSTOM: [
        "custom-model",
    ],
}


# =============================================================================
# SECURITY SCAN CHECKLIST - Comprehensive list for LLM analysis
# =============================================================================

SECURITY_SCAN_CHECKLIST = """
# DRAGONSHIELD COMPREHENSIVE SECURITY SCAN CHECKLIST
Execute these checks systematically. Batch related commands for efficiency.

## PHASE 1: SYSTEM RECONNAISSANCE (Gather Context)

### 1.1 System Identity & Environment
1. Determine OS distribution, version, and codename (lsb_release -a, /etc/os-release)
2. Check kernel version and potential vulnerabilities (uname -r, uname -a)
3. Identify system architecture (arch, uname -m)
4. Check system uptime and last reboot (uptime, last reboot)
5. Detect virtualization type (systemd-detect-virt, virt-what, dmidecode)
6. Check hostname and domain settings (hostname -f, /etc/hostname, /etc/hosts)
7. Identify if system is a container (/.dockerenv, /run/.containerenv, cgroups)

### 1.2 Hardware & Resources
8. Check CPU information for VM detection (lscpu, /proc/cpuinfo)
9. Check memory info (free -h, /proc/meminfo)
10. Check disk usage and mounts (df -h, mount, /proc/mounts)
11. Identify block devices (lsblk, fdisk -l)

## PHASE 2: USER & AUTHENTICATION SECURITY

### 2.1 User Account Analysis
12. List all users with login shells (/etc/passwd analysis)
13. Identify users with UID 0 (root equivalent accounts)
14. Find users with empty passwords (getent shadow analysis)
15. Check for duplicate UIDs and GIDs
16. Identify users without home directories
17. Find orphaned files (no valid owner)
18. Check /etc/passwd and /etc/shadow permissions
19. Analyze /etc/group for privileged group memberships
20. Check for users in sudo/wheel/admin groups

### 2.2 Password & Authentication Policies
21. Review password aging settings (chage -l for users)
22. Check /etc/login.defs for password policies
23. Analyze PAM configuration (/etc/pam.d/*)
24. Check password complexity requirements (pam_pwquality)
25. Verify account lockout policies (pam_faillock, faillock)
26. Check for password hashing algorithm strength
27. Review /etc/security/pwquality.conf

### 2.3 Sudo & Privilege Escalation
28. Analyze sudoers file (/etc/sudoers, /etc/sudoers.d/*)
29. Find NOPASSWD entries in sudoers
30. Check for ALL=(ALL) NOPASSWD: ALL entries
31. Identify sudo command restrictions
32. Check sudo log configuration
33. Verify sudoers file permissions (should be 0440)

### 2.4 Login Security
34. Check last login records (lastlog, last)
35. Analyze failed login attempts (/var/log/btmp, faillog)
36. Review /var/log/auth.log or /var/log/secure
37. Check /etc/securetty for root login restrictions
38. Verify /etc/security/access.conf

## PHASE 3: SSH SECURITY

### 3.1 SSH Daemon Configuration
39. Analyze sshd_config for security settings
40. Check PermitRootLogin setting (should be no or prohibit-password)
41. Verify PasswordAuthentication setting
42. Check Protocol version (only 2 allowed)
43. Review PermitEmptyPasswords (must be no)
44. Check MaxAuthTries setting (recommend 3-5)
45. Verify LoginGraceTime setting
46. Check AllowUsers/AllowGroups/DenyUsers/DenyGroups
47. Review X11Forwarding setting
48. Check AllowAgentForwarding
49. Verify AllowTcpForwarding
50. Check StrictModes setting (should be yes)
51. Review Ciphers and MACs for weak algorithms
52. Check KexAlgorithms for weak key exchange
53. Verify HostKey algorithms used
54. Check Banner configuration

### 3.2 SSH Keys & Files
55. Check ~/.ssh directory permissions (should be 700)
56. Verify authorized_keys permissions (should be 600)
57. Check private key permissions (should be 600)
58. Look for weak SSH keys (DSA, small RSA)
59. Check for authorized_keys with dangerous options
60. Scan for exposed private keys in common locations

## PHASE 4: NETWORK SECURITY

### 4.1 Network Configuration
61. List all network interfaces (ip addr, ifconfig)
62. Check listening ports (ss -tulpn, netstat -tulpn)
63. Identify unexpected listening services
64. Check active connections (ss -tupn)
65. Look for connections to suspicious IPs
66. Check DNS configuration (/etc/resolv.conf)
67. Review /etc/hosts for malicious entries
68. Check IP forwarding status (sysctl net.ipv4.ip_forward)

### 4.2 Firewall Analysis
69. Check iptables/nftables rules (iptables -L -n -v)
70. Verify ufw status if installed (ufw status verbose)
71. Check firewalld status if used (firewall-cmd --list-all)
72. Identify overly permissive rules
73. Check for missing egress filtering
74. Verify default policies (should be DROP)

### 4.3 Network Services
75. Check for exposed database ports (3306, 5432, 27017, 6379)
76. Identify unencrypted service ports (21, 23, 110, 143)
77. Check NFS exports (/etc/exports, showmount -e localhost)
78. Review Samba shares (smb.conf, smbstatus)
79. Check SNMP configuration if present
80. Verify NTP configuration (/etc/ntp.conf, chrony)

## PHASE 5: FILESYSTEM SECURITY

### 5.1 Dangerous Permissions
81. Find world-writable files (find / -perm -0002 -type f)
82. Find world-writable directories without sticky bit
83. Locate SUID binaries (find / -perm -4000)
84. Locate SGID binaries (find / -perm -2000)
85. Compare SUID/SGID against known-good lists
86. Find files with no owner (find / -nouser)
87. Find files with no group (find / -nogroup)

### 5.2 Critical File Permissions
88. Verify /etc/passwd permissions (should be 644)
89. Verify /etc/shadow permissions (should be 600 or 640)
90. Check /etc/group permissions (should be 644)
91. Check /etc/gshadow permissions (should be 600)
92. Verify crontab file permissions
93. Check /etc/ssh/sshd_config permissions
94. Verify bootloader config permissions

### 5.3 Mount Options
95. Check mount options for /tmp (noexec, nosuid, nodev)
96. Check mount options for /var/tmp
97. Check mount options for /home
98. Check mount options for /dev/shm
99. Verify separate partitions for critical directories
100. Check for hidepid on /proc

### 5.4 Temporary Directories
101. Check /tmp permissions and cleanup
102. Verify /var/tmp configuration
103. Check sticky bit on shared directories

## PHASE 6: KERNEL & SYSTEM HARDENING

### 6.1 Kernel Security Parameters
104. Check ASLR status (/proc/sys/kernel/randomize_va_space)
105. Verify ExecShield or similar protections
106. Check kptr_restrict (/proc/sys/kernel/kptr_restrict)
107. Verify dmesg_restrict (/proc/sys/kernel/dmesg_restrict)
108. Check perf_event_paranoid
109. Check ptrace scope (kernel.yama.ptrace_scope)
110. Review sysctl.conf for security settings

### 6.2 Kernel Modules
111. List loaded kernel modules (lsmod)
112. Check for suspicious/unexpected modules
113. Verify module loading restrictions
114. Check /etc/modprobe.d/ for blacklisted modules
115. Verify USB storage restrictions if applicable

### 6.3 Mandatory Access Control
116. Check SELinux status and mode (getenforce, sestatus)
117. Check AppArmor status (aa-status)
118. Identify unconfined processes if MAC enabled
119. Review MAC policy violations in logs

## PHASE 7: SERVICE & PROCESS SECURITY

### 7.1 Running Services
120. List all running services (systemctl list-units --type=service)
121. Identify unnecessary services
122. Check for legacy/insecure services (telnet, rsh, rlogin)
123. Verify services are running as non-root where possible
124. Check for services listening on 0.0.0.0

### 7.2 Process Analysis
125. List all running processes with details (ps auxf)
126. Check for processes running as root unnecessarily
127. Look for suspicious process names
128. Check for cryptocurrency mining processes
129. Identify hidden processes
130. Check for processes with deleted binaries

### 7.3 Container Security
131. Check Docker daemon configuration
132. Verify Docker socket permissions (/var/run/docker.sock)
133. Look for privileged containers
134. Check container capabilities
135. Verify container network isolation
136. Check for exposed container ports

## PHASE 8: SCHEDULED TASKS & PERSISTENCE

### 8.1 Cron Analysis
137. Check system crontabs (/etc/crontab, /etc/cron.d/*)
138. Review hourly/daily/weekly/monthly crons
139. List all user crontabs (for user in users; crontab -l -u $user)
140. Check cron permissions (/etc/cron.allow, /etc/cron.deny)
141. Look for suspicious cron entries

### 8.2 Other Scheduled Tasks
142. Check anacron configuration
143. List at jobs (atq)
144. Check systemd timers (systemctl list-timers)

### 8.3 Persistence Mechanisms
145. Check /etc/rc.local
146. Review init scripts (/etc/init.d/)
147. Check systemd unit files for modifications
148. Look for unusual .bashrc/.profile entries
149. Check /etc/profile.d/ scripts
150. Verify LD_PRELOAD is not hijacked
151. Check /etc/ld.so.preload

## PHASE 9: LOGGING & AUDITING

### 9.1 Log Configuration
152. Check syslog/rsyslog configuration
153. Verify journald configuration
154. Check log rotation (logrotate config)
155. Verify critical logs are being written
156. Check for remote logging configuration

### 9.2 Audit System
157. Check if auditd is installed and running
158. Review audit rules (/etc/audit/audit.rules)
159. Check audit log permissions
160. Verify key audit events are captured

### 9.3 Command History
161. Check HISTSIZE and HISTFILESIZE
162. Verify HISTCONTROL settings
163. Check for history logging to syslog
164. Review bash history for suspicious commands

## PHASE 10: SOFTWARE & PACKAGE SECURITY

### 10.1 Package Management
165. Check for available security updates
166. List installed packages
167. Check package integrity (debsums, rpm -Va)
168. Review repository sources
169. Verify GPG key verification is enabled
170. Check for unofficial/suspicious repositories

### 10.2 Software Analysis
171. Check for known vulnerable packages
172. Look for development tools on production (gcc, make)
173. Check for unnecessary network tools (nmap, netcat in suspicious locations)
174. Verify installed interpreters (python, perl, php)

## PHASE 11: CRYPTOGRAPHY & SECRETS

### 11.1 SSL/TLS Configuration
175. Check SSL/TLS certificate validity
176. Look for expiring certificates
177. Check for self-signed certificates in production
178. Verify SSL/TLS versions (disable SSLv3, TLSv1.0, TLSv1.1)
179. Check cipher suite configuration

### 11.2 Key Management
180. Check for exposed private keys
181. Verify key file permissions
182. Look for hardcoded credentials in common files
183. Check environment variables for secrets
184. Scan for .env files with credentials

### 11.3 Entropy
185. Check available entropy (/proc/sys/kernel/random/entropy_avail)
186. Verify random number generator sources

## PHASE 12: BOOT & PHYSICAL SECURITY

### 12.1 Bootloader Security
187. Check GRUB password protection
188. Verify bootloader file permissions
189. Check Secure Boot status if applicable

### 12.2 Physical Security
190. Check Ctrl+Alt+Del behavior
191. Verify Magic SysRq settings
192. Check USB port restrictions if applicable
193. Verify console access restrictions

## PHASE 13: MALWARE & ROOTKIT DETECTION

### 13.1 Rootkit Checks
194. Check for known rootkit files and directories
195. Look for hidden files in / and common directories
196. Check for suspicious .bashrc additions
197. Verify system binary integrity
198. Check /dev for suspicious files
199. Look for suspicious entries in /etc

### 13.2 Backdoor Detection
200. Check for unusual SUID shells
201. Look for authorized_keys in unexpected locations
202. Check for suspicious system users
203. Verify no unexpected network listeners
204. Check for reverse shell processes

## PHASE 14: APPLICATION-SPECIFIC SECURITY

### 14.1 Web Server (if present)
205. Check Apache/Nginx configuration
206. Verify directory listing disabled
207. Check for exposed .git directories
208. Verify sensitive file protection
209. Check SSL/TLS configuration

### 14.2 Database (if present)
210. Check database authentication
211. Verify network binding (localhost only if not needed)
212. Check default credentials
213. Verify encryption at rest/transit

## PHASE 15: COMPLIANCE CHECKS

### 15.1 CIS Benchmark Items
214. Verify compliance with CIS Level 1 controls
215. Check password requirements match policy
216. Verify logging meets requirements
217. Check file permissions match standards

### 15.2 General Best Practices
218. Verify principle of least privilege
219. Check separation of duties
220. Verify defense in depth measures
221. Check backup configuration (if accessible)

## OUTPUT FORMAT
After gathering information, provide a structured report with:
- Critical findings (immediate action required)
- High severity issues (should fix soon)
- Medium severity issues (should address)
- Low severity issues (nice to fix)
- Informational findings (awareness)

For each finding, provide:
- Description of the issue
- Risk/impact explanation
- Specific fix command (if applicable)
- Manual fix instructions if no command is available
"""


SYSTEM_PROMPT = f"""You are DragonShield, an advanced Linux security analyzer.
Your mission is to perform comprehensive security analysis by executing commands and analyzing their outputs.

CRITICAL RULES:
1. DEFENSIVE operations only - gather information and identify fixes
2. Never execute destructive or offensive commands
3. Respect [REDACTED] content - it contains private data
4. Batch multiple commands together for efficiency
5. Be thorough but avoid redundant checks

{SECURITY_SCAN_CHECKLIST}

OUTPUT FORMAT - Always respond with valid JSON:

To execute commands (batch them):
{{
    "action": "execute",
    "commands": [
        {{"cmd": "command1", "purpose": "why running this"}},
        {{"cmd": "command2", "purpose": "why running this"}}
    ],
    "phase": "current scan phase description"
}}

To provide final report:
{{
    "action": "report",
    "summary": "Overall security assessment",
    "risk_score": "critical|high|medium|low",
    "findings": [
        {{
            "severity": "critical|high|medium|low|info",
            "category": "category name",
            "issue": "detailed description",
            "impact": "what could happen",
            "fix_cmd": "command to fix or null if manual",
            "manual_fix": "instructions if no command"
        }}
    ],
    "recommendations": ["prioritized list of actions"]
}}

Begin comprehensive security analysis now. Start with Phase 1 to gather system context."""


# =============================================================================
# DRAGON ASCII ART
# =============================================================================

DRAGON_LOGO = """[bold red]
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⡤⠀⢀⡀⣀⢱⡄⡀⠀⠀⠀⢲⣤⣤⣤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⡿⠛⠋⠁⣤⣿⣿⣿⣧⣷⠀⠀⠘⠉⠛⢻⣷⣿⣽⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣞⣽⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠠⣿⣿⡟⢻⣿⣿⣇⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣟⢦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣿⡾⣿⣿⣿⣿⣿⠿⣻⣿⣿⡀⠀⠀⠀⢻⣿⣷⡀⠻⣧⣿⠆⠀⠀⠀⠀⣿⣿⣿⡻⣿⣿⣿⣿⣿⠿⣽⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣼⠟⣩⣾⣿⣿⣿⢟⣵⣿⣿⣿⣿⣧⠀⠀⠀⠈⠿⣿⣿⣷⣈⠁⠀⠀⠀⠀⣰⣿⣿⣿⣷⡹⣿⣿⣿⣿⣿⢿⣿⣮⡳⡄⠀⠀
⠀⢀⡜⣡⣾⣿⢿⣿⣿⣿⣿⣿⣿⢟⣵⣿⣿⣿⣷⣄⠀⣰⣿⣿⣿⣿⣿⣷⣄⠀⢀⣼⣿⣿⣿⣷⡹⣿⣿⣿⣿⣿⣿⢿⣿⣮⡳⡄⠀⠀
⢠⢟⣿⡿⠋⣠⣾⢿⣿⣿⠟⢃⣾⢟⣿⢿⣿⣿⣿⣾⡿⠟⠻⣿⣻⣿⣏⠻⣿⣾⣿⣿⣿⣿⣿⡛⣿⡌⠻⣿⣿⡿⣿⣦⡙⢿⣿⡝⣆⠀
⢯⣿⠏⣠⠞⠋⠀⣠⡿⠋⢀⣿⠁⢸⡏⣿⠿⣿⣿⠃⢠⣴⣾⣿⣿⣿⡟⠀⠘⢹⣿⠟⣿⣾⣷⠈⣿⡄⠘⢿⣦⠀⠈⠻⣆⠙⣿⣜⠆
⢀⣿⠃⡴⠃⢀⡠⠞⠋⠀⠀⠼⠋⠀⠸⡇⠻⠀⠈⠃⠀⣧⢋⣼⣿⣿⣿⣷⣆⠀⠈⠁⠀⠟⠁⡟⠀⠈⠻⠀⠀⠉⠳⢦⡀⢣⠈⢿⡄
⣸⠇⢠⣷⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠋⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣆⠈⣷
⡟⠀⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣤⡀⢸⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⢹
⡇⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠶⣶⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⢸
⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠶⣶⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼
⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                       ⢿⣿⣤⣀⣠⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
[/]"""

TITLE_TEXT = "[bold #ff0000]DRAGON[/][bold #8b0000]SHIELD[/] [dim #ff4444]SYSTEM GUARD[/]"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ChatMessage:
    role: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)


# =============================================================================
# CONFIGURATION MANAGER
# =============================================================================

class ConfigManager:
    def __init__(self):
        self.config = DEFAULT_CONFIG.copy()
        self.load_config()
    
    def load_config(self) -> None:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH, "r") as f:
                    self.config.update(json.load(f))
            except Exception:
                pass
    
    def save_config(self) -> None:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(self.config, f, indent=2)
    
    def get(self, key: str, default=None):
        return self.config.get(key, default)
    
    def set(self, key: str, value) -> None:
        self.config[key] = value
        self.save_config()
    
    def get_current_provider(self) -> LLMProvider:
        return LLMProvider(self.get("llm_provider", LLMProvider.OPENROUTER.value))
    
    def get_current_model(self) -> str:
        provider = self.get_current_provider()
        if provider == LLMProvider.OPENROUTER:
            return self.get("model", AVAILABLE_MODELS[LLMProvider.OPENROUTER][0])
        elif provider == LLMProvider.OLLAMA:
            return self.get("ollama_model", AVAILABLE_MODELS[LLMProvider.OLLAMA][0])
        elif provider == LLMProvider.OPENAI_COMPATIBLE:
            return self.get("openai_model", "local-model")
        else:
            return self.get("custom_model", "custom-model")
    
    def get_current_base_url(self) -> str:
        provider = self.get_current_provider()
        if provider == LLMProvider.OPENROUTER:
            return self.get("openrouter_base_url", "https://openrouter.ai/api/v1")
        elif provider == LLMProvider.OLLAMA:
            return self.get("ollama_base_url", "http://localhost:11434")
        elif provider == LLMProvider.OPENAI_COMPATIBLE:
            return self.get("openai_base_url", "http://localhost:1234/v1")
        else:
            return self.get("custom_base_url", "http://localhost:8080")


# =============================================================================
# LLM PROVIDER HANDLERS
# =============================================================================

class LLMProviderHandler:
    """Base class for LLM provider handlers."""
    
    def __init__(self, config: ConfigManager, http_client: httpx.AsyncClient):
        self.config = config
        self.http_client = http_client
    
    async def call(self, messages: list[dict]) -> str:
        raise NotImplementedError


class OpenRouterHandler(LLMProviderHandler):
    """Handler for OpenRouter API."""
    
    async def call(self, messages: list[dict]) -> str:
        api_key = self.config.get("api_key")
        if not api_key:
            raise ValueError("OpenRouter API key not set")
        
        base_url = self.config.get("openrouter_base_url", "https://openrouter.ai/api/v1")
        
        response = await self.http_client.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://dragonshield.local",
                "X-Title": "DragonShield",
            },
            json={
                "model": self.config.get("model"),
                "messages": messages,
                "temperature": self.config.get("temperature", 0.2),
                "max_tokens": self.config.get("max_tokens", 4096),
            },
        )
        
        if response.status_code != 200:
            raise Exception(f"OpenRouter API error {response.status_code}: {response.text[:500]}")
        
        return response.json()["choices"][0]["message"]["content"]


class OllamaHandler(LLMProviderHandler):
    """Handler for Ollama API (native format)."""
    
    async def call(self, messages: list[dict]) -> str:
        base_url = self.config.get("ollama_base_url", "http://localhost:11434")
        model = self.config.get("ollama_model", "llama3.1:8b")
        
        # Try OpenAI-compatible endpoint first (newer Ollama versions)
        try:
            response = await self.http_client.post(
                f"{base_url}/v1/chat/completions",
                headers={"Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": self.config.get("temperature", 0.2),
                    "stream": False,
                },
                timeout=300.0,  # Longer timeout for local models
            )
            
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
        except Exception:
            pass
        
        # Fall back to native Ollama API
        response = await self.http_client.post(
            f"{base_url}/api/chat",
            headers={"Content-Type": "application/json"},
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": self.config.get("temperature", 0.2),
                },
            },
            timeout=300.0,
        )
        
        if response.status_code != 200:
            raise Exception(f"Ollama API error {response.status_code}: {response.text[:500]}")
        
        return response.json()["message"]["content"]


class OpenAICompatibleHandler(LLMProviderHandler):
    """Handler for OpenAI-compatible APIs (LM Studio, LocalAI, vLLM, etc.)."""
    
    async def call(self, messages: list[dict]) -> str:
        base_url = self.config.get("openai_base_url", "http://localhost:1234/v1")
        model = self.config.get("openai_model", "local-model")
        api_key = self.config.get("api_key", "not-needed")  # Some local servers need a placeholder
        
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        response = await self.http_client.post(
            f"{base_url}/chat/completions",
            headers=headers,
            json={
                "model": model,
                "messages": messages,
                "temperature": self.config.get("temperature", 0.2),
                "max_tokens": self.config.get("max_tokens", 4096),
                "stream": False,
            },
            timeout=300.0,
        )
        
        if response.status_code != 200:
            raise Exception(f"API error {response.status_code}: {response.text[:500]}")
        
        return response.json()["choices"][0]["message"]["content"]


class CustomHandler(LLMProviderHandler):
    """Handler for custom API endpoints."""
    
    async def call(self, messages: list[dict]) -> str:
        base_url = self.config.get("custom_base_url", "http://localhost:8080")
        model = self.config.get("custom_model", "model")
        api_key = self.config.get("custom_api_key", "")
        
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        # Try OpenAI format first
        try:
            endpoint = f"{base_url}/v1/chat/completions"
            if not base_url.endswith("/v1"):
                endpoint = f"{base_url}/chat/completions"
            
            response = await self.http_client.post(
                endpoint,
                headers=headers,
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": self.config.get("temperature", 0.2),
                    "max_tokens": self.config.get("max_tokens", 4096),
                },
                timeout=300.0,
            )
            
            if response.status_code == 200:
                data = response.json()
                if "choices" in data:
                    return data["choices"][0]["message"]["content"]
                elif "message" in data:
                    return data["message"]["content"]
                elif "response" in data:
                    return data["response"]
                elif "content" in data:
                    return data["content"]
        except Exception as e:
            raise Exception(f"Custom API error: {e}")
        
        raise Exception(f"Custom API error {response.status_code}: {response.text[:500]}")


# =============================================================================
# SECURITY ENGINE
# =============================================================================

class SecurityEngine:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.chat_history: list[ChatMessage] = []
        self.http_client = httpx.AsyncClient(timeout=120.0)
        self._handlers: dict[LLMProvider, LLMProviderHandler] = {
            LLMProvider.OPENROUTER: OpenRouterHandler(config, self.http_client),
            LLMProvider.OLLAMA: OllamaHandler(config, self.http_client),
            LLMProvider.OPENAI_COMPATIBLE: OpenAICompatibleHandler(config, self.http_client),
            LLMProvider.CUSTOM: CustomHandler(config, self.http_client),
        }
    
    def is_path_excluded(self, path: str) -> bool:
        for exc in self.config.get("excluded_paths", []):
            if path.startswith(exc):
                return True
        return False
    
    def should_redact(self, text: str) -> bool:
        for pattern in self.config.get("redacted_patterns", []):
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def redact_sensitive(self, text: str) -> str:
        lines = []
        for line in text.split("\n"):
            if self.should_redact(line):
                lines.append("[REDACTED]")
            elif re.search(r"/mnt/[a-z]/", line):
                lines.append("[REDACTED:WINDOWS]")
            else:
                lines.append(line)
        return "\n".join(lines)
    
    def is_command_safe(self, cmd: str) -> tuple[bool, str]:
        cmd_lower = cmd.lower().strip()
        for pattern in self.config.get("dangerous_commands", []):
            if re.search(pattern, cmd_lower):
                return False, f"Blocked: {pattern}"
        return True, "OK"
    
    async def execute_command(self, cmd: str) -> tuple[bool, str]:
        is_safe, reason = self.is_command_safe(cmd)
        if not is_safe:
            return False, reason
        
        try:
            timeout = self.config.get("command_timeout", 60)
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            output = stdout.decode("utf-8", errors="replace")
            if stderr:
                output += "\n" + stderr.decode("utf-8", errors="replace")
            
            return True, self.redact_sensitive(output[:30000])
        except asyncio.TimeoutError:
            return False, f"Timeout ({timeout}s)"
        except Exception as e:
            return False, str(e)
    
    async def execute_batch(self, commands: list[dict]) -> list[dict]:
        results = []
        for cmd_info in commands:
            cmd = cmd_info.get("cmd", "")
            success, output = await self.execute_command(cmd)
            results.append({
                "cmd": cmd,
                "purpose": cmd_info.get("purpose", ""),
                "success": success,
                "output": output
            })
        return results
    
    async def call_llm(self, messages: list[dict]) -> str:
        provider = self.config.get_current_provider()
        handler = self._handlers.get(provider)
        
        if not handler:
            raise ValueError(f"Unknown provider: {provider}")
        
        return await handler.call(messages)
    
    def parse_response(self, response: str) -> dict:
        match = re.search(r"\{[\s\S]*\}", response)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return {"action": "text", "content": response}
    
    async def test_connection(self) -> tuple[bool, str]:
        """Test connection to current LLM provider."""
        try:
            provider = self.config.get_current_provider()
            
            if provider == LLMProvider.OLLAMA:
                # Test Ollama by listing models
                base_url = self.config.get("ollama_base_url", "http://localhost:11434")
                response = await self.http_client.get(f"{base_url}/api/tags", timeout=10.0)
                if response.status_code == 200:
                    models = [m["name"] for m in response.json().get("models", [])]
                    return True, f"Connected. Models: {', '.join(models[:5])}"
                return False, f"Status {response.status_code}"
            
            elif provider == LLMProvider.OPENAI_COMPATIBLE:
                # Test by listing models
                base_url = self.config.get("openai_base_url", "http://localhost:1234/v1")
                response = await self.http_client.get(f"{base_url}/models", timeout=10.0)
                if response.status_code == 200:
                    return True, "Connected to OpenAI-compatible API"
                # Some servers don't support /models, try a simple completion
                return True, "Endpoint reachable"
            
            elif provider == LLMProvider.OPENROUTER:
                api_key = self.config.get("api_key")
                if not api_key:
                    return False, "API key not set"
                return True, "API key configured"
            
            else:
                base_url = self.config.get("custom_base_url")
                response = await self.http_client.get(base_url, timeout=10.0)
                return True, f"Endpoint reachable (status {response.status_code})"
        
        except httpx.ConnectError:
            return False, "Connection refused - is the server running?"
        except httpx.TimeoutException:
            return False, "Connection timeout"
        except Exception as e:
            return False, str(e)
    
    async def close(self):
        await self.http_client.aclose()


# =============================================================================
# STYLES - Red & Black Theme
# =============================================================================

CSS = """
/* BASE THEME */
Screen {
    background: #000000;
    color: #ffcccc;
}

/* LAYOUT STRUCTURE */
#top-container {
    height: auto;
    width: 100%;
    align: center middle;
    padding-top: 1;
}

#logo {
    text-align: center;
    color: #ff0000;
    height: auto;
    margin-bottom: 0;
}

#title {
    text-align: center;
    margin-bottom: 1;
}

#menu-container {
    width: 50;
    height: auto;
    border: heavy #8b0000;
    background: #050000;
    margin-bottom: 1;
}

OptionList {
    background: transparent;
    border: none;
    height: auto;
    max-height: 8;
    scrollbar-color: #ff0000;
}

OptionList:focus {
    border: none;
}

OptionList > .option-list--option {
    padding: 0 2;
    color: #ff8888;
}

OptionList > .option-list--option-highlighted {
    background: #8b0000;
    color: #ffffff;
    text-style: bold;
}

OptionList > .option-list--option-hover {
    background: #330000;
}

#chat-scroll {
    height: 1fr;
    border-top: heavy #ff0000;
    background: #080000;
    scrollbar-color: #ff0000;
    padding: 1;
}

#status-line {
    height: 1;
    dock: bottom;
    background: #330000;
    color: #ffaaaa;
    padding: 0 1;
}

/* CHAT MESSAGE STYLES */
.msg-box {
    padding: 0 1;
    margin: 0 0 1 0;
}

.msg-system {
    border-left: tall #550000;
    color: #aa4444;
}

.msg-assistant {
    border-left: tall #ff0000;
    color: #ffcccc;
}

.msg-command {
    border-left: tall #ff4500;
    color: #ff8800;
}

.msg-result {
    border-left: tall #800000;
    color: #ff9999;
}

.msg-error {
    border-left: tall #ff0000;
    color: #ff0000;
    text-style: bold;
}

.msg-fix {
    border-left: tall #ff1493;
    color: #ff69b4;
}

/* MODAL STYLES */
#modal-box {
    width: 80;
    height: auto;
    max-height: 90%;
    border: heavy #ff0000;
    background: #0a0000;
    padding: 1 2;
}

#modal-title {
    text-align: center;
    color: #ff0000;
    text-style: bold;
    padding-bottom: 1;
}

Label {
    color: #ffaaaa;
    margin-top: 1;
}

Input {
    background: #1a0000;
    border: solid #550000;
    color: #ffffff;
}

Input:focus {
    border: solid #ff0000;
}

TextArea {
    background: #1a0000;
    border: solid #550000;
    color: #ffcccc;
    height: 10;
}

TextArea:focus {
    border: solid #ff0000;
}

Button {
    margin: 1 1 0 0;
    background: #330000;
    color: #ffcccc;
    border: none;
}

Button:hover {
    background: #550000;
}

Button.-primary {
    background: #8b0000;
    color: #ffffff;
}

Button.-primary:hover {
    background: #ff0000;
}

/* RADIO BUTTONS */
RadioSet {
    background: transparent;
    border: none;
    height: auto;
    margin: 1 0;
}

RadioButton {
    background: transparent;
    color: #ff8888;
    padding: 0 1;
}

RadioButton:hover {
    background: #330000;
}

RadioButton.-selected {
    color: #ffffff;
}

/* SELECT */
Select {
    background: #1a0000;
    border: solid #550000;
    color: #ffcccc;
}

Select:focus {
    border: solid #ff0000;
}

/* LIST VIEW */
ListView {
    height: auto;
    max-height: 10;
    background: #0a0000;
    border: solid #550000;
}

ListView:focus {
    border: solid #ff0000;
}

ListItem {
    color: #ff8888;
}

ListItem:hover {
    background: #330000;
}

ListItem.-selected {
    background: #8b0000;
    color: #ffffff;
}

Rule {
    color: #8b0000;
}

Footer {
    background: #220000;
    color: #ff0000;
}

/* PROVIDER SECTION */
.provider-section {
    border: solid #550000;
    padding: 1;
    margin: 1 0;
    background: #0a0000;
}

.section-title {
    color: #ff4444;
    text-style: bold;
}

.connection-status {
    color: #888888;
    text-style: italic;
}

.status-ok {
    color: #44ff44;
}

.status-error {
    color: #ff4444;
}
"""


# =============================================================================
# MODAL SCREENS
# =============================================================================

class SettingsModal(ModalScreen[bool]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]
    
    def __init__(self, config: ConfigManager, engine: SecurityEngine):
        super().__init__()
        self.config = config
        self.engine = engine
    
    def compose(self) -> ComposeResult:
        current_provider = self.config.get_current_provider()
        
        with Container(id="modal-box"):
            yield Label("LLM PROVIDER CONFIGURATION", id="modal-title")
            yield Rule()
            
            # Provider Selection
            yield Label("Select LLM Provider:", classes="section-title")
            with RadioSet(id="provider-select"):
                yield RadioButton(
                    "OpenRouter (Cloud API)", 
                    id="radio-openrouter",
                    value=current_provider == LLMProvider.OPENROUTER
                )
                yield RadioButton(
                    "Ollama (Local)", 
                    id="radio-ollama",
                    value=current_provider == LLMProvider.OLLAMA
                )
                yield RadioButton(
                    "OpenAI-Compatible (LM Studio, LocalAI, etc.)", 
                    id="radio-openai",
                    value=current_provider == LLMProvider.OPENAI_COMPATIBLE
                )
                yield RadioButton(
                    "Custom Endpoint", 
                    id="radio-custom",
                    value=current_provider == LLMProvider.CUSTOM
                )
            
            yield Static("", id="connection-status", classes="connection-status")
            
            # OpenRouter Section
            with Vertical(id="section-openrouter", classes="provider-section"):
                yield Label("OpenRouter Settings", classes="section-title")
                yield Label("API Key:")
                yield Input(
                    value=self.config.get("api_key", ""), 
                    password=True, 
                    id="inp-openrouter-key",
                    placeholder="sk-or-..."
                )
                yield Label("Model:")
                yield Select(
                    [(m, m) for m in AVAILABLE_MODELS[LLMProvider.OPENROUTER]],
                    value=self.config.get("model", AVAILABLE_MODELS[LLMProvider.OPENROUTER][0]),
                    id="sel-openrouter-model"
                )
            
            # Ollama Section
            with Vertical(id="section-ollama", classes="provider-section"):
                yield Label("Ollama Settings", classes="section-title")
                yield Label("Base URL:")
                yield Input(
                    value=self.config.get("ollama_base_url", "http://localhost:11434"),
                    id="inp-ollama-url",
                    placeholder="http://localhost:11434"
                )
                yield Label("Model:")
                yield Input(
                    value=self.config.get("ollama_model", "llama3.1:8b"),
                    id="inp-ollama-model",
                    placeholder="llama3.1:8b"
                )
            
            # OpenAI-Compatible Section  
            with Vertical(id="section-openai", classes="provider-section"):
                yield Label("OpenAI-Compatible API Settings", classes="section-title")
                yield Label("Base URL:")
                yield Input(
                    value=self.config.get("openai_base_url", "http://localhost:1234/v1"),
                    id="inp-openai-url",
                    placeholder="http://localhost:1234/v1"
                )
                yield Label("Model Name:")
                yield Input(
                    value=self.config.get("openai_model", "local-model"),
                    id="inp-openai-model",
                    placeholder="local-model"
                )
                yield Label("API Key (optional):")
                yield Input(
                    value=self.config.get("api_key", ""),
                    password=True,
                    id="inp-openai-key",
                    placeholder="Leave empty if not required"
                )
            
            # Custom Section
            with Vertical(id="section-custom", classes="provider-section"):
                yield Label("Custom Endpoint Settings", classes="section-title")
                yield Label("Base URL:")
                yield Input(
                    value=self.config.get("custom_base_url", "http://localhost:8080"),
                    id="inp-custom-url"
                )
                yield Label("Model Name:")
                yield Input(
                    value=self.config.get("custom_model", "model"),
                    id="inp-custom-model"
                )
                yield Label("API Key (optional):")
                yield Input(
                    value=self.config.get("custom_api_key", ""),
                    password=True,
                    id="inp-custom-key"
                )
            
            yield Rule()
            
            # General Settings
            yield Label("General Settings", classes="section-title")
            with Horizontal():
                with Vertical():
                    yield Label("Command Timeout (sec):")
                    yield Input(
                        value=str(self.config.get("command_timeout", 60)), 
                        id="inp-timeout"
                    )
                with Vertical():
                    yield Label("Max Iterations:")
                    yield Input(
                        value=str(self.config.get("max_iterations", 10)), 
                        id="inp-iter"
                    )
                with Vertical():
                    yield Label("Temperature:")
                    yield Input(
                        value=str(self.config.get("temperature", 0.2)),
                        id="inp-temp"
                    )
            
            with Horizontal():
                yield Button("TEST CONNECTION", id="btn-test")
                yield Button("SAVE", variant="primary", id="btn-save")
                yield Button("CANCEL", id="btn-cancel")
    
    def on_mount(self) -> None:
        self._update_section_visibility()
    
    def _update_section_visibility(self) -> None:
        """Show only the section for the selected provider."""
        radio_set = self.query_one("#provider-select", RadioSet)
        
        # Determine which radio is selected
        provider = LLMProvider.OPENROUTER
        if self.query_one("#radio-ollama", RadioButton).value:
            provider = LLMProvider.OLLAMA
        elif self.query_one("#radio-openai", RadioButton).value:
            provider = LLMProvider.OPENAI_COMPATIBLE
        elif self.query_one("#radio-custom", RadioButton).value:
            provider = LLMProvider.CUSTOM
        
        # Show/hide sections
        sections = {
            LLMProvider.OPENROUTER: "#section-openrouter",
            LLMProvider.OLLAMA: "#section-ollama",
            LLMProvider.OPENAI_COMPATIBLE: "#section-openai",
            LLMProvider.CUSTOM: "#section-custom",
        }
        
        for prov, selector in sections.items():
            try:
                section = self.query_one(selector)
                section.display = (prov == provider)
            except Exception:
                pass
    
    @on(RadioSet.Changed, "#provider-select")
    def on_provider_change(self, event: RadioSet.Changed) -> None:
        self._update_section_visibility()
        self.query_one("#connection-status", Static).update("")
    
    @on(Button.Pressed, "#btn-test")
    async def test_connection(self) -> None:
        self._save_current_settings()
        status_widget = self.query_one("#connection-status", Static)
        status_widget.update("[yellow]Testing connection...[/]")
        
        success, message = await self.engine.test_connection()
        
        if success:
            status_widget.update(f"[green]✓ {message}[/]")
        else:
            status_widget.update(f"[red]✗ {message}[/]")
    
    def _save_current_settings(self) -> None:
        """Save current form values to config."""
        # Determine provider
        if self.query_one("#radio-openrouter", RadioButton).value:
            self.config.set("llm_provider", LLMProvider.OPENROUTER.value)
        elif self.query_one("#radio-ollama", RadioButton).value:
            self.config.set("llm_provider", LLMProvider.OLLAMA.value)
        elif self.query_one("#radio-openai", RadioButton).value:
            self.config.set("llm_provider", LLMProvider.OPENAI_COMPATIBLE.value)
        else:
            self.config.set("llm_provider", LLMProvider.CUSTOM.value)
        
        # Save provider-specific settings
        self.config.set("api_key", self.query_one("#inp-openrouter-key", Input).value)
        
        try:
            self.config.set("model", self.query_one("#sel-openrouter-model", Select).value)
        except Exception:
            pass
        
        self.config.set("ollama_base_url", self.query_one("#inp-ollama-url", Input).value)
        self.config.set("ollama_model", self.query_one("#inp-ollama-model", Input).value)
        
        self.config.set("openai_base_url", self.query_one("#inp-openai-url", Input).value)
        self.config.set("openai_model", self.query_one("#inp-openai-model", Input).value)
        
        self.config.set("custom_base_url", self.query_one("#inp-custom-url", Input).value)
        self.config.set("custom_model", self.query_one("#inp-custom-model", Input).value)
        self.config.set("custom_api_key", self.query_one("#inp-custom-key", Input).value)
        
        # General settings
        try:
            self.config.set("command_timeout", int(self.query_one("#inp-timeout", Input).value))
            self.config.set("max_iterations", int(self.query_one("#inp-iter", Input).value))
            self.config.set("temperature", float(self.query_one("#inp-temp", Input).value))
        except ValueError:
            pass
    
    @on(Button.Pressed, "#btn-save")
    def action_save(self) -> None:
        self._save_current_settings()
        self.dismiss(True)
    
    @on(Button.Pressed, "#btn-cancel")
    def action_cancel(self) -> None:
        self.dismiss(False)


class ExclusionsModal(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    
    def __init__(self, config: ConfigManager):
        super().__init__()
        self.config = config
    
    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Label("EXCLUSION PROTOCOLS", id="modal-title")
            yield Rule()
            yield Label("Restricted Paths (one per line):")
            yield TextArea("\n".join(self.config.get("excluded_paths", [])), id="ta-paths")
            yield Label("Redaction Patterns (regex):")
            yield TextArea("\n".join(self.config.get("redacted_patterns", [])), id="ta-patterns")
            with Horizontal():
                yield Button("SAVE", variant="primary", id="btn-save")
                yield Button("CANCEL", id="btn-cancel")
    
    @on(Button.Pressed, "#btn-save")
    def save(self) -> None:
        paths = [p.strip() for p in self.query_one("#ta-paths", TextArea).text.split("\n") if p.strip()]
        patterns = [p.strip() for p in self.query_one("#ta-patterns", TextArea).text.split("\n") if p.strip()]
        self.config.set("excluded_paths", paths)
        self.config.set("redacted_patterns", patterns)
        self.dismiss(True)
    
    @on(Button.Pressed, "#btn-cancel")
    def action_cancel(self) -> None:
        self.dismiss(False)


class ConfirmFixModal(ModalScreen[bool]):
    BINDINGS = [
        Binding("y", "confirm", "Yes"),
        Binding("n", "deny", "No"),
        Binding("escape", "deny", "Cancel"),
    ]
    
    def __init__(self, commands: list[str]):
        super().__init__()
        self.commands = commands
    
    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Label("AUTHORIZE FIX EXECUTION?", id="modal-title")
            yield Rule()
            yield Label("Pending Commands:")
            
            content = "\n".join(f"  > {c}" for c in self.commands[:15])
            yield Static(f"[#ffcccc]{content}[/]")
            
            if len(self.commands) > 15:
                yield Label(f"  ... and {len(self.commands) - 15} more")
            yield Rule()
            with Horizontal():
                yield Button("EXECUTE", variant="primary", id="btn-yes")
                yield Button("ABORT", id="btn-no")
    
    @on(Button.Pressed, "#btn-yes")
    def action_confirm(self) -> None:
        self.dismiss(True)
    
    @on(Button.Pressed, "#btn-no")
    def action_deny(self) -> None:
        self.dismiss(False)


# =============================================================================
# MAIN APPLICATION
# =============================================================================

class DragonShieldApp(App):
    CSS = CSS
    TITLE = "DragonShield"
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("1", "menu_scan", "Scan", show=False),
        Binding("2", "menu_settings", "Settings", show=False),
        Binding("3", "menu_exclusions", "Exclusions", show=False),
        Binding("4", "menu_clear", "Clear", show=False),
        Binding("5", "quit", "Quit", show=False),
        Binding("escape", "stop", "Stop scan"),
    ]
    
    def __init__(self):
        super().__init__()
        self.config = ConfigManager()
        self.engine = SecurityEngine(self.config)
        self.is_scanning = False
        self.pending_fixes: list[str] = []
    
    def compose(self) -> ComposeResult:
        with Vertical(id="top-container"):
            yield Static(DRAGON_LOGO, id="logo")
            yield Static(TITLE_TEXT, id="title")
            
            with Center():
                with Vertical(id="menu-container"):
                    yield OptionList(
                        Option(" [1] INITIATE SCAN PROCEDURE", id="opt-scan"),
                        Option(" [2] SYSTEM CONFIGURATION", id="opt-settings"),
                        Option(" [3] EXCLUSION PROTOCOLS", id="opt-exclusions"),
                        Option(" [4] PURGE LOGS", id="opt-clear"),
                        Option(" [5] TERMINATE SESSION", id="opt-quit"),
                        id="main-menu"
                    )
        
        yield ScrollableContainer(id="chat-scroll")
        yield Static("READY | [Q]UIT [1-5]MENU [ESC]STOP", id="status-line")
        yield Footer()
    
    def on_mount(self) -> None:
        self.query_one("#main-menu", OptionList).focus()
        
        provider = self.config.get_current_provider()
        model = self.config.get_current_model()
        
        self.log_msg("system", "DragonShield Security System Online.")
        self.log_msg("system", 
            f"Privilege Level: {'[bold red]ROOT[/]' if os.geteuid() == 0 else '[yellow]LIMITED USER[/]'}\n"
            f"LLM Provider: [cyan]{provider.value}[/]\n"
            f"Model: [cyan]{model}[/]\n"
            "Waiting for command input..."
        )
        
        if os.geteuid() != 0:
            self.log_msg("error", "WARNING: Root privileges missing. Scan capabilities limited.")
        
        # Check provider configuration
        if provider == LLMProvider.OPENROUTER and not self.config.get("api_key"):
            self.log_msg("system", "OpenRouter API Key missing. Please configure settings.")
    
    def log_msg(self, role: str, content: str) -> None:
        container = self.query_one("#chat-scroll", ScrollableContainer)
        
        if role == "assistant":
            widget = Static(Markdown(content), classes=f"msg-box msg-{role}")
        elif role in ("command", "result", "error", "fix"):
            # Escape markup characters in command/result output to prevent parsing errors
            escaped = content.replace("[", r"\[").replace("]", r"\]")
            widget = Static(escaped, classes=f"msg-box msg-{role}")
        else:
            # System messages - content as-is
            widget = Static(content, classes=f"msg-box msg-{role}")
            
        container.mount(widget)
        container.scroll_end(animate=False)
    
    def update_status(self, text: str) -> None:
        self.query_one("#status-line", Static).update(text.upper())
    
    @on(OptionList.OptionSelected, "#main-menu")
    def on_menu_select(self, event: OptionList.OptionSelected) -> None:
        option_id = event.option.id
        if option_id == "opt-scan":
            self.action_menu_scan()
        elif option_id == "opt-settings":
            self.action_menu_settings()
        elif option_id == "opt-exclusions":
            self.action_menu_exclusions()
        elif option_id == "opt-clear":
            self.action_menu_clear()
        elif option_id == "opt-quit":
            self.exit()
    
    def action_menu_scan(self) -> None:
        if self.is_scanning:
            self.notify("Scan already in progress", severity="warning")
            return
        
        provider = self.config.get_current_provider()
        if provider == LLMProvider.OPENROUTER and not self.config.get("api_key"):
            self.notify("OpenRouter API Key Required", severity="error")
            return
        
        self.run_scan()
    
    def action_menu_settings(self) -> None:
        self.push_screen(SettingsModal(self.config, self.engine))
    
    def action_menu_exclusions(self) -> None:
        self.push_screen(ExclusionsModal(self.config))
    
    def action_menu_clear(self) -> None:
        container = self.query_one("#chat-scroll", ScrollableContainer)
        container.remove_children()
        self.log_msg("system", "Log buffer purged.")
    
    def action_stop(self) -> None:
        if self.is_scanning:
            self.is_scanning = False
            self.log_msg("error", "Scan sequence aborted manually.")
            self.update_status("Stopped")
    
    @work(exclusive=True, thread=False)
    async def run_scan(self) -> None:
        self.is_scanning = True
        self.pending_fixes = []
        
        provider = self.config.get_current_provider()
        model = self.config.get_current_model()
        
        self.log_msg("system", f"Initializing scan using {provider.value} / {model}...")
        self.update_status("SCANNING...")
        
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Perform comprehensive security analysis of this Linux system. Start with Phase 1 reconnaissance commands batched together."}
        ]
        
        max_iter = self.config.get("max_iterations", 10)
        
        try:
            for i in range(max_iter):
                if not self.is_scanning:
                    break
                
                self.update_status(f"SCANNING... ITERATION {i+1}/{max_iter}")
                
                response = await self.engine.call_llm(messages)
                parsed = self.engine.parse_response(response)
                action = parsed.get("action", "text")
                
                if action == "execute":
                    commands = parsed.get("commands", [])
                    phase = parsed.get("phase", "")
                    
                    if phase:
                        self.log_msg("assistant", f"**{phase}** - Executing {len(commands)} command(s)...")
                    else:
                        self.log_msg("assistant", f"Executing {len(commands)} command(s)...")
                    
                    results = await self.engine.execute_batch(commands)
                    
                    result_text = []
                    for r in results:
                        status = "SUCCESS" if r["success"] else "FAILED"
                        self.log_msg("command", f"> {r['cmd']}\n# {r['purpose']}")
                        
                        output = r["output"][:1500]
                        if len(r["output"]) > 1500:
                            output += "\n[...truncated]"
                        # Escape output to prevent markup parsing errors
                        safe_output = output.replace("[", r"\[").replace("]", r"\]") if output.strip() else "(no output)"
                        self.log_msg("result", safe_output)
                        
                        result_text.append(
                            f"CMD: {r['cmd']}\nSTATUS: {status}\nOUTPUT:\n{r['output'][:3000]}"
                        )
                    
                    messages.append({"role": "assistant", "content": response})
                    messages.append({"role": "user", "content": "Results:\n\n" + "\n\n---\n\n".join(result_text)})
                
                elif action == "report":
                    summary = parsed.get("summary", "")
                    risk_score = parsed.get("risk_score", "unknown").upper()
                    
                    self.log_msg("assistant", f"# SECURITY REPORT\n\n**Risk Level: {risk_score}**\n\n{summary}")
                    
                    findings = parsed.get("findings", [])
                    for f in findings:
                        sev = f.get("severity", "low").upper()
                        icon = {"CRITICAL": "☠️", "HIGH": "🔥", "MEDIUM": "⚠️", "LOW": "ℹ️", "INFO": "📝"}.get(sev, "?")
                        category = f.get("category", "General")
                        
                        msg = f"{icon} **[{sev}]** [{category}]\n\n{f.get('issue', 'Unknown')}"
                        if f.get("impact"):
                            msg += f"\n\n**Impact:** {f['impact']}"
                        if f.get("fix_cmd"):
                            msg += f"\n\n**Fix:** `{f['fix_cmd']}`"
                        elif f.get("manual_fix"):
                            msg += f"\n\n**Manual Fix:** {f['manual_fix']}"
                        
                        self.log_msg("assistant", msg)
                        
                        if f.get("fix_cmd"):
                            self.pending_fixes.append(f["fix_cmd"])
                    
                    recommendations = parsed.get("recommendations", [])
                    if recommendations:
                        self.log_msg("assistant", "## Recommendations\n\n" + "\n".join(f"- {r}" for r in recommendations))
                    
                    self.is_scanning = False
                    self.update_status("SCAN COMPLETE")
                    
                    if self.pending_fixes:
                        self.log_msg("system", f"\n{len(self.pending_fixes)} automated fix(es) available.")
                        self.prompt_fixes()
                    break
                
                else:
                    self.log_msg("assistant", parsed.get("content", response))
                    messages.append({"role": "assistant", "content": response})
                    messages.append({"role": "user", "content": "Continue with the next phase of analysis or provide final report."})
            
            else:
                self.log_msg("error", f"Iteration limit ({max_iter}) reached. Requesting final report...")
                messages.append({"role": "user", "content": "Provide final security report now with all findings gathered so far."})
                response = await self.engine.call_llm(messages)
                parsed = self.engine.parse_response(response)
                self.log_msg("assistant", parsed.get("summary", response))
        
        except Exception as e:
            self.log_msg("error", f"CRITICAL ERROR: {e}")
        
        finally:
            self.is_scanning = False
            self.update_status("READY")
    
    def prompt_fixes(self) -> None:
        def handle_result(result: bool) -> None:
            if result:
                self.apply_fixes()
        
        self.push_screen(ConfirmFixModal(self.pending_fixes), handle_result)
    
    @work(exclusive=True, thread=False)
    async def apply_fixes(self) -> None:
        self.log_msg("fix", "APPLYING SECURITY PATCHES...")
        self.update_status("PATCHING...")
        
        for cmd in self.pending_fixes:
            self.log_msg("command", f"> {cmd}")
            success, output = await self.engine.execute_command(cmd)
            
            if success:
                self.log_msg("result", output if output.strip() else "(done)")
            else:
                self.log_msg("error", f"FAILED: {output}")
        
        self.log_msg("fix", "Patching sequence finished.")
        self.pending_fixes = []
        self.update_status("READY")
    
    async def on_unmount(self) -> None:
        await self.engine.close()


def main():
    if sys.version_info < (3, 10):
        print("Python 3.10+ required")
        sys.exit(1)
    
    app = DragonShieldApp()
    app.run()


if __name__ == "__main__":
    main()