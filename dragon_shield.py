#!/usr/bin/env python3
"""
DragonShield v2 - Linux System Security Panel
Redesigned Interface: Center Layout, Red Scale Theme.
"""

import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

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
)
from textual.widgets.option_list import Option

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG_PATH = Path.home() / ".config" / "dragonshield" / "config.json"

DEFAULT_CONFIG = {
    "api_key": "",
    "model": "anthropic/claude-3.5-sonnet",
    "max_iterations": 10,
    "command_timeout": 60,
    "auto_fix": False,
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

AVAILABLE_MODELS = [
    "mistralai/devstral-2512:free",
    "anthropic/claude-3-haiku",
    "openai/gpt-4o",
    "openai/gpt-4o-mini",
    "google/gemini-pro-1.5",
    "google/gemini-flash-1.5",
    "meta-llama/llama-3.1-70b-instruct",
    "mistralai/mistral-large",
    "deepseek/deepseek-chat",
]

SYSTEM_PROMPT = """You are DragonShield, a Linux security analyzer.
Analyze security posture by requesting commands and analyzing outputs.

RULES:
1. DEFENSIVE tool only - no offensive actions
2. Only gather info or fix security issues
3. Never damage the system
4. Respect REDACTED content (privacy)

OUTPUT FORMAT - Always respond with valid JSON:

To execute commands (batch them together):
{
    "action": "execute",
    "commands": [
        {"cmd": "command1", "purpose": "why"},
        {"cmd": "command2", "purpose": "why"}
    ]
}

To provide final report:
{
    "action": "report",
    "summary": "Overall security assessment",
    "findings": [
        {"severity": "critical|high|medium|low", "issue": "description", "fix_cmd": "command or null"}
    ]
}

Batch multiple commands in single request for efficiency.
Start gathering system information now."""


# =============================================================================
# DRAGON ASCII ART
# =============================================================================

DRAGON_LOGO = """[bold red]
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⡼⠀⢀⡀⣀⢱⡄⡀⠀⠀⠀⢲⣤⣤⣤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⡿⠛⠋⠁⣤⣿⣿⣿⣧⣷⠀⠀⠘⠉⠛⢻⣷⣿⣽⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣞⣽⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠠⣿⣿⡟⢻⣿⣿⣇⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣟⢦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣿⡾⣿⣿⣿⣿⣿⠿⣻⣿⣿⡀⠀⠀⠀⢻⣿⣷⡀⠻⣧⣿⠆⠀⠀⠀⠀⣿⣿⣿⡻⣿⣿⣿⣿⣿⠿⣽⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣼⠟⣩⣾⣿⣿⣿⢟⣵⣾⣿⣿⣿⣧⠀⠀⠀⠈⠿⣿⣿⣷⣈⠁⠀⠀⠀⠀⣰⣿⣿⣿⣿⣮⣟⢯⣿⣿⣷⣬⡻⣷⡄⠀⠀⠀
⠀⠀⢀⡜⣡⣾⣿⢿⣿⣿⣿⣿⣿⢟⣵⣿⣿⣿⣷⣄⠀⣰⣿⣿⣿⣿⣿⣷⣄⠀⢀⣼⣿⣿⣿⣷⡹⣿⣿⣿⣿⣿⣿⢿⣿⣮⡳⡄⠀⠀
⠀⢠⢟⣿⡿⠋⣠⣾⢿⣿⣿⠟⢃⣾⢟⣿⢿⣿⣿⣿⣾⡿⠟⠻⣿⣻⣿⣏⠻⣿⣾⣿⣿⣿⣿⡛⣿⡌⠻⣿⣿⡿⣿⣦⡙⢿⣿⡝⣆⠀
⠀⢯⣿⠏⣠⠞⠋⠀⣠⡿⠋⢀⣿⠁⢸⡏⣿⠿⣿⣿⠃⢠⣴⣾⣿⣿⣿⡟⠀⠘⢹⣿⠟⣿⣾⣷⠈⣿⡄⠘⢿⣦⠀⠈⠻⣆⠙⣿⣜⠆
⢀⣿⠃⡴⠃⢀⡠⠞⠋⠀⠀⠼⠋⠀⠸⡇⠻⠀⠈⠃⠀⣧⢋⣼⣿⣿⣿⣷⣆⠀⠈⠁⠀⠟⠁⡟⠀⠈⠻⠀⠀⠉⠳⢦⡀⠈⢣⠈⢿⡄
⣸⠇⢠⣷⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠋⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢾⣆⠈⣷
⡟⠀⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣤⡀⢸⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⢹
⡇⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠈⣿⣼⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⢸
⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠶⣶⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼
⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁
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


# =============================================================================
# SECURITY ENGINE
# =============================================================================

class SecurityEngine:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.chat_history: list[ChatMessage] = []
        self.http_client = httpx.AsyncClient(timeout=120.0)
    
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
        api_key = self.config.get("api_key")
        if not api_key:
            raise ValueError("API key not set")
        
        response = await self.http_client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://dragonshield.local",
                "X-Title": "DragonShield",
            },
            json={
                "model": self.config.get("model"),
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 4096,
            },
        )
        
        if response.status_code != 200:
            raise Exception(f"API error {response.status_code}: {response.text[:200]}")
        
        return response.json()["choices"][0]["message"]["content"]
    
    def parse_response(self, response: str) -> dict:
        match = re.search(r"\{[\s\S]*\}", response)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return {"action": "text", "content": response}
    
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
    width: 70;
    height: auto;
    max-height: 85%;
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
"""


# =============================================================================
# MODAL SCREENS
# =============================================================================

class SettingsModal(ModalScreen[bool]):
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "save", "Save", show=False),
    ]
    
    def __init__(self, config: ConfigManager):
        super().__init__()
        self.config = config
    
    def compose(self) -> ComposeResult:
        with Container(id="modal-box"):
            yield Label("SYSTEM CONFIGURATION", id="modal-title")
            yield Rule()
            yield Label("API Key:")
            yield Input(value=self.config.get("api_key", ""), password=True, id="inp-key")
            yield Label("AI Model:")
            yield ListView(
                *[ListItem(Label(m), id=f"m{i}") for i, m in enumerate(AVAILABLE_MODELS)],
                id="model-list"
            )
            yield Label(f"Current: {self.config.get('model')}", id="current-model")
            yield Label("Timeout (sec):")
            yield Input(value=str(self.config.get("command_timeout", 60)), id="inp-timeout")
            yield Label("Max Iterations:")
            yield Input(value=str(self.config.get("max_iterations", 10)), id="inp-iter")
            with Horizontal():
                yield Button("SAVE", variant="primary", id="btn-save")
                yield Button("CANCEL", id="btn-cancel")
    
    @on(ListView.Selected, "#model-list")
    def on_model_select(self, event: ListView.Selected) -> None:
        idx = int(event.item.id[1:])
        self.config.set("model", AVAILABLE_MODELS[idx])
        self.query_one("#current-model", Label).update(f"Current: {AVAILABLE_MODELS[idx]}")
    
    @on(Button.Pressed, "#btn-save")
    def action_save(self) -> None:
        self.config.set("api_key", self.query_one("#inp-key", Input).value)
        try:
            self.config.set("command_timeout", int(self.query_one("#inp-timeout", Input).value))
            self.config.set("max_iterations", int(self.query_one("#inp-iter", Input).value))
        except ValueError:
            pass
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
            
            # FIXED: Removed style argument, used markup instead
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
        # Top Section: Dragon Logo and Centered Menu
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
        
        # Bottom Section: Chat Log
        yield ScrollableContainer(id="chat-scroll")
        yield Static("READY | [Q]UIT [1-5]MENU [ESC]STOP", id="status-line")
        yield Footer()
    
    def on_mount(self) -> None:
        self.query_one("#main-menu", OptionList).focus()
        self.log_msg("system", "DragonShield Security System Online.")
        self.log_msg("system", 
            f"Privilege Level: {'[bold red]ROOT[/]' if os.geteuid() == 0 else '[yellow]LIMITED USER[/]'}\n"
            "Waiting for command input..."
        )
        
        if os.geteuid() != 0:
            self.log_msg("error", "WARNING: Root privileges missing. Scan capabilities limited.")
        
        if not self.config.get("api_key"):
            self.log_msg("system", "API Key missing. Please configure settings.")
    
    def log_msg(self, role: str, content: str) -> None:
        container = self.query_one("#chat-scroll", ScrollableContainer)
        
        # Ensure markdown renders cleanly in red theme
        if role == "assistant":
            widget = Static(Markdown(content), classes=f"msg-box msg-{role}")
        else:
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
        if not self.config.get("api_key"):
            self.notify("API Key Required", severity="error")
            return
        self.run_scan()
    
    def action_menu_settings(self) -> None:
        self.push_screen(SettingsModal(self.config))
    
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
        
        self.log_msg("system", f"Initializing scan protocol using {self.config.get('model')}...")
        self.update_status("SCANNING...")
        
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Analyze this Linux system security. Batch your commands."}
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
                    self.log_msg("assistant", f"Executing {len(commands)} command(s)...")
                    
                    results = await self.engine.execute_batch(commands)
                    
                    result_text = []
                    for r in results:
                        status = "SUCCESS" if r["success"] else "FAILED"
                        self.log_msg("command", f"> {r['cmd']}\n# {r['purpose']}")
                        
                        output = r["output"][:1500]
                        if len(r["output"]) > 1500:
                            output += "\n[...truncated]"
                        self.log_msg("result", output if output.strip() else "(no output)")
                        
                        result_text.append(
                            f"CMD: {r['cmd']}\nSTATUS: {status}\nOUTPUT:\n{r['output'][:3000]}"
                        )
                    
                    messages.append({"role": "assistant", "content": response})
                    messages.append({"role": "user", "content": "Results:\n\n" + "\n\n---\n\n".join(result_text)})
                
                elif action == "report":
                    self.log_msg("assistant", "# SECURITY REPORT\n\n" + parsed.get("summary", ""))
                    
                    findings = parsed.get("findings", [])
                    for f in findings:
                        sev = f.get("severity", "low").upper()
                        # Red-themed icons
                        icon = {"CRITICAL": "☠️", "HIGH": "🔥", "MEDIUM": "⚠️", "LOW": "ℹ️"}.get(sev, "?")
                        self.log_msg("assistant", 
                            f"{icon} **[{sev}]** {f.get('issue', 'Unknown')}\n\n"
                            f"Fix: `{f.get('fix_cmd', 'manual review needed')}`"
                        )
                        
                        if f.get("fix_cmd"):
                            self.pending_fixes.append(f["fix_cmd"])
                    
                    self.is_scanning = False
                    self.update_status("SCAN COMPLETE")
                    
                    if self.pending_fixes:
                        self.log_msg("system", f"\n{len(self.pending_fixes)} fix(es) identified.")
                        self.prompt_fixes()
                    break
                
                else:
                    self.log_msg("assistant", parsed.get("content", response))
                    messages.append({"role": "assistant", "content": response})
                    messages.append({"role": "user", "content": "Continue analysis or provide final report."})
            
            else:
                self.log_msg("error", f"Iteration limit ({max_iter}) reached.")
        
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