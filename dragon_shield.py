#!/usr/bin/env python3
"""
DragonShield - Linux System Security Panel
Cyber-Dragon themed TUI for Linux security using LLM in agent mode.
Uses OpenRouter as LLM provider with MCP-style tool execution.
"""

import asyncio
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from rich.markdown import Markdown
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    LoadingIndicator,
    Static,
    TextArea,
)

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG_PATH = Path.home() / ".config" / "dragonshield" / "config.json"
DATA_PATH = Path.home() / ".config" / "dragonshield" / "data.json"

DEFAULT_CONFIG = {
    "api_key": "",
    "model": "anthropic/claude-3.5-sonnet",
    "max_iterations": 10,
    "command_timeout": 60,
    "excluded_paths": [
        "/mnt/c",
        "/mnt/d",
        "/mnt/e",
        "/mnt/wsl",
        "/proc",
        "/sys",
        "/dev",
    ],
    "redacted_patterns": [
        r".*\.pem$",
        r".*\.key$",
        r".*id_rsa.*",
        r".*id_ed25519.*",
        r".*\.env$",
        r".*password.*",
        r".*secret.*",
        r".*token.*",
        r".*\.ssh/.*",
        r".*/\.gnupg/.*",
    ],
    "dangerous_commands": [
        "rm -rf /",
        "mkfs",
        "dd if=",
        ":(){:|:&};:",
        "> /dev/sda",
        "chmod -R 777 /",
        "wget.*|.*sh",
        "curl.*|.*sh",
    ],
}

AVAILABLE_MODELS = [
    "mistralai/devstral-2512:free",
    "anthropic/claude-4-sonnet",
    "openai/gpt-5",
    "openai/gpt-5-mini",
    "google/gemini-pro-2.5",
    "meta-llama/llama-3.1-70b-instruct",
    "mistralai/mistral-large",
    "deepseek/deepseek-chat",
]

SYSTEM_PROMPT = """You are DragonShield, an advanced Linux system security analyzer.
Your role is to analyze the security posture of a Linux system by requesting
command executions and analyzing their outputs.

IMPORTANT RULES:
1. You are a DEFENSIVE security tool - never suggest offensive actions
2. Only request commands that gather information or fix security issues
3. Never request commands that could damage the system
4. Always explain why you need each command
5. Respect user privacy - some paths/files are REDACTED for privacy

WORKFLOW:
1. Start by gathering basic system information
2. Analyze security configurations
3. Check for vulnerabilities
4. Provide actionable recommendations

OUTPUT FORMAT:
When you need to execute commands, respond with JSON:
{
    "action": "execute",
    "commands": [
        {"cmd": "command here", "reason": "why this command"}
    ]
}

When you have enough information for a report:
{
    "action": "report",
    "summary": "Brief security assessment",
    "findings": [
        {"severity": "high|medium|low", "issue": "description", "fix": "command or action"}
    ],
    "fix_commands": ["list of commands to fix issues"]
}

Start by gathering essential system information."""


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ChatMessage:
    """Represents a message in the chat history."""
    role: str  # "system", "user", "assistant", "command", "result"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScanResult:
    """Represents a completed security scan result."""
    timestamp: datetime
    summary: str
    findings: list
    fix_commands: list
    chat_history: list


# =============================================================================
# CONFIGURATION MANAGER
# =============================================================================

class ConfigManager:
    """Manages application configuration and data persistence."""
    
    def __init__(self):
        self.config = DEFAULT_CONFIG.copy()
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file."""
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH, "r") as f:
                    loaded = json.load(f)
                    self.config.update(loaded)
            except Exception:
                pass
    
    def save_config(self) -> None:
        """Save configuration to file."""
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(self.config, f, indent=2)
    
    def get(self, key: str, default=None):
        """Get configuration value."""
        return self.config.get(key, default)
    
    def set(self, key: str, value) -> None:
        """Set configuration value."""
        self.config[key] = value
        self.save_config()


# =============================================================================
# SECURITY ENGINE
# =============================================================================

class SecurityEngine:
    """Handles command execution and LLM interaction."""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.chat_history: list[ChatMessage] = []
        self.http_client = httpx.AsyncClient(timeout=120.0)
    
    def is_path_excluded(self, path: str) -> bool:
        """Check if path should be excluded from scanning."""
        excluded = self.config.get("excluded_paths", [])
        for exc in excluded:
            if path.startswith(exc):
                return True
        return False
    
    def should_redact(self, text: str) -> bool:
        """Check if content should be redacted."""
        patterns = self.config.get("redacted_patterns", [])
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def redact_sensitive(self, text: str) -> str:
        """Redact sensitive information from text."""
        lines = text.split("\n")
        redacted_lines = []
        
        for line in lines:
            # Redact file paths that match patterns
            if self.should_redact(line):
                redacted_lines.append("[REDACTED - Sensitive file/content]")
            # Redact Windows paths in WSL
            elif re.search(r"/mnt/[a-z]/", line):
                redacted_lines.append("[REDACTED - Windows filesystem]")
            else:
                redacted_lines.append(line)
        
        return "\n".join(redacted_lines)
    
    def is_command_safe(self, cmd: str) -> tuple[bool, str]:
        """Check if command is safe to execute."""
        dangerous = self.config.get("dangerous_commands", [])
        cmd_lower = cmd.lower()
        
        for pattern in dangerous:
            if re.search(pattern, cmd_lower):
                return False, f"Blocked dangerous pattern: {pattern}"
        
        # Additional safety checks
        if "sudo" in cmd and "rm" in cmd and "-rf" in cmd:
            return False, "Blocked: dangerous rm -rf with sudo"
        
        return True, "OK"
    
    async def execute_command(self, cmd: str) -> tuple[bool, str]:
        """Execute a shell command safely."""
        is_safe, reason = self.is_command_safe(cmd)
        if not is_safe:
            return False, f"Command blocked: {reason}"
        
        try:
            timeout = self.config.get("command_timeout", 60)
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            
            output = stdout.decode("utf-8", errors="replace")
            if stderr:
                output += "\n[STDERR]\n" + stderr.decode("utf-8", errors="replace")
            
            # Redact sensitive information
            output = self.redact_sensitive(output)
            
            return True, output[:50000]  # Limit output size
            
        except asyncio.TimeoutError:
            return False, f"Command timed out after {timeout}s"
        except Exception as e:
            return False, f"Execution error: {str(e)}"
    
    async def call_llm(self, messages: list[dict]) -> str:
        """Call OpenRouter API."""
        api_key = self.config.get("api_key")
        if not api_key:
            raise ValueError("API key not configured")
        
        model = self.config.get("model", "anthropic/claude-3.5-sonnet")
        
        response = await self.http_client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/dragonshield",
                "X-Title": "DragonShield Security Panel",
            },
            json={
                "model": model,
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 4096,
            },
        )
        
        if response.status_code != 200:
            raise Exception(f"API error: {response.status_code} - {response.text}")
        
        data = response.json()
        return data["choices"][0]["message"]["content"]
    
    def parse_llm_response(self, response: str) -> dict:
        """Parse LLM response to extract JSON action."""
        # Try to find JSON in response
        json_match = re.search(r"\{[\s\S]*\}", response)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        
        # Return as plain text if no JSON found
        return {"action": "text", "content": response}
    
    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()


# =============================================================================
# TUI STYLES
# =============================================================================

CSS = """
$dragon-red: #dc143c;
$dragon-dark-red: #8b0000;
$dragon-black: #0a0a0a;
$dragon-gray: #1a1a1a;
$dragon-light: #2a2a2a;
$dragon-text: #e0e0e0;
$dragon-accent: #ff4444;

Screen {
    background: $dragon-black;
}

Header {
    background: $dragon-dark-red;
    color: $dragon-text;
    text-style: bold;
}

Footer {
    background: $dragon-gray;
    color: $dragon-text;
}

#main-container {
    width: 100%;
    height: 100%;
    background: $dragon-black;
}

#sidebar {
    width: 30;
    background: $dragon-gray;
    border-right: solid $dragon-dark-red;
    padding: 1;
}

#content {
    width: 100%;
    background: $dragon-black;
}

#chat-container {
    width: 100%;
    height: 100%;
    background: $dragon-black;
    border: solid $dragon-dark-red;
    padding: 1;
}

#input-container {
    height: 3;
    dock: bottom;
    background: $dragon-gray;
    padding: 0 1;
}

.menu-button {
    width: 100%;
    margin: 0 0 1 0;
    background: $dragon-light;
    color: $dragon-text;
    border: tall $dragon-dark-red;
}

.menu-button:hover {
    background: $dragon-dark-red;
    color: white;
}

.menu-button:focus {
    background: $dragon-red;
    color: white;
    text-style: bold;
}

.chat-message {
    width: 100%;
    padding: 1;
    margin: 0 0 1 0;
    background: $dragon-gray;
    border-left: tall $dragon-dark-red;
}

.chat-message.assistant {
    border-left: tall $dragon-red;
    background: $dragon-light;
}

.chat-message.command {
    border-left: tall #ffaa00;
    background: #1a1500;
}

.chat-message.result {
    border-left: tall #00aa00;
    background: #001500;
}

.chat-message.error {
    border-left: tall #ff0000;
    background: #150000;
}

.status-bar {
    height: 1;
    background: $dragon-gray;
    color: $dragon-text;
    padding: 0 1;
    text-align: center;
}

#logo {
    text-align: center;
    color: $dragon-red;
    text-style: bold;
    padding: 1;
}

.section-title {
    text-align: center;
    color: $dragon-accent;
    text-style: bold;
    padding: 0 0 1 0;
    border-bottom: solid $dragon-dark-red;
    margin-bottom: 1;
}

ModalScreen {
    align: center middle;
}

#modal-container {
    width: 60;
    height: auto;
    max-height: 80%;
    background: $dragon-gray;
    border: tall $dragon-red;
    padding: 1 2;
}

#modal-title {
    text-align: center;
    text-style: bold;
    color: $dragon-red;
    padding-bottom: 1;
    border-bottom: solid $dragon-dark-red;
    margin-bottom: 1;
}

Input {
    background: $dragon-light;
    border: tall $dragon-dark-red;
    color: $dragon-text;
}

Input:focus {
    border: tall $dragon-red;
}

TextArea {
    background: $dragon-light;
    border: tall $dragon-dark-red;
}

ListView {
    background: $dragon-gray;
    border: tall $dragon-dark-red;
    height: auto;
    max-height: 15;
}

ListItem {
    background: $dragon-light;
    color: $dragon-text;
    padding: 0 1;
}

ListItem:hover {
    background: $dragon-dark-red;
}

ListItem.-selected {
    background: $dragon-red;
    color: white;
}

LoadingIndicator {
    color: $dragon-red;
}

#report-container {
    width: 100%;
    height: 100%;
    background: $dragon-black;
    padding: 1;
}

.finding-high {
    background: #2a0000;
    border-left: tall #ff0000;
    padding: 1;
    margin-bottom: 1;
}

.finding-medium {
    background: #2a1a00;
    border-left: tall #ffaa00;
    padding: 1;
    margin-bottom: 1;
}

.finding-low {
    background: #1a2a00;
    border-left: tall #aaff00;
    padding: 1;
    margin-bottom: 1;
}
"""


# =============================================================================
# MODAL SCREENS
# =============================================================================

class SettingsScreen(ModalScreen[bool]):
    """Settings configuration modal."""
    
    def __init__(self, config: ConfigManager):
        super().__init__()
        self.config = config
    
    def compose(self) -> ComposeResult:
        with Container(id="modal-container"):
            yield Label("DRAGONSHIELD SETTINGS", id="modal-title")
            yield Label("OpenRouter API Key:")
            yield Input(
                value=self.config.get("api_key", ""),
                password=True,
                id="api-key-input",
                placeholder="sk-or-..."
            )
            yield Label("Select Model:")
            yield ListView(
                *[ListItem(Label(m), id=f"model-{i}") 
                  for i, m in enumerate(AVAILABLE_MODELS)],
                id="model-list"
            )
            yield Label("Command Timeout (seconds):")
            yield Input(
                value=str(self.config.get("command_timeout", 60)),
                id="timeout-input"
            )
            yield Label("Max LLM Iterations:")
            yield Input(
                value=str(self.config.get("max_iterations", 10)),
                id="iterations-input"
            )
            with Horizontal():
                yield Button("Save", variant="primary", id="save-btn")
                yield Button("Cancel", id="cancel-btn")
    
    @on(Button.Pressed, "#save-btn")
    def save_settings(self) -> None:
        api_key = self.query_one("#api-key-input", Input).value
        timeout = self.query_one("#timeout-input", Input).value
        iterations = self.query_one("#iterations-input", Input).value
        
        self.config.set("api_key", api_key)
        try:
            self.config.set("command_timeout", int(timeout))
            self.config.set("max_iterations", int(iterations))
        except ValueError:
            pass
        
        self.dismiss(True)
    
    @on(Button.Pressed, "#cancel-btn")
    def cancel(self) -> None:
        self.dismiss(False)
    
    @on(ListView.Selected, "#model-list")
    def select_model(self, event: ListView.Selected) -> None:
        index = int(event.item.id.split("-")[1])
        self.config.set("model", AVAILABLE_MODELS[index])


class ExclusionsScreen(ModalScreen[bool]):
    """Privacy exclusions configuration modal."""
    
    def __init__(self, config: ConfigManager):
        super().__init__()
        self.config = config
    
    def compose(self) -> ComposeResult:
        excluded = self.config.get("excluded_paths", [])
        with Container(id="modal-container"):
            yield Label("PRIVACY EXCLUSIONS", id="modal-title")
            yield Label("Excluded Paths (one per line):")
            yield TextArea(
                "\n".join(excluded),
                id="excluded-paths",
            )
            yield Label("Redacted File Patterns (regex, one per line):")
            yield TextArea(
                "\n".join(self.config.get("redacted_patterns", [])),
                id="redacted-patterns",
            )
            with Horizontal():
                yield Button("Save", variant="primary", id="save-btn")
                yield Button("Cancel", id="cancel-btn")
    
    @on(Button.Pressed, "#save-btn")
    def save_settings(self) -> None:
        paths = self.query_one("#excluded-paths", TextArea).text
        patterns = self.query_one("#redacted-patterns", TextArea).text
        
        self.config.set("excluded_paths", [p.strip() for p in paths.split("\n") if p.strip()])
        self.config.set("redacted_patterns", [p.strip() for p in patterns.split("\n") if p.strip()])
        
        self.dismiss(True)
    
    @on(Button.Pressed, "#cancel-btn")
    def cancel(self) -> None:
        self.dismiss(False)


class ReportScreen(ModalScreen[None]):
    """Security report display modal."""
    
    def __init__(self, report: dict):
        super().__init__()
        self.report = report
    
    def compose(self) -> ComposeResult:
        with ScrollableContainer(id="modal-container"):
            yield Label("SECURITY REPORT", id="modal-title")
            yield Static(Markdown(f"## Summary\n\n{self.report.get('summary', 'No summary')}"))
            
            yield Label("Findings:", classes="section-title")
            for finding in self.report.get("findings", []):
                severity = finding.get("severity", "low")
                yield Static(
                    Markdown(f"**[{severity.upper()}]** {finding.get('issue', '')}\n\n"
                            f"**Fix:** {finding.get('fix', 'N/A')}"),
                    classes=f"finding-{severity}"
                )
            
            if self.report.get("fix_commands"):
                yield Label("Fix Commands:", classes="section-title")
                yield Static(Markdown("```bash\n" + 
                    "\n".join(self.report.get("fix_commands", [])) + 
                    "\n```"))
            
            yield Button("Close", id="close-btn")
    
    @on(Button.Pressed, "#close-btn")
    def close_report(self) -> None:
        self.dismiss(None)


# =============================================================================
# MAIN APPLICATION
# =============================================================================

class DragonShieldApp(App):
    """Main DragonShield TUI Application."""
    
    TITLE = "DragonShield Security Panel"
    CSS = CSS
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "scan", "Scan"),
        Binding("c", "settings", "Config"),
        Binding("escape", "stop_scan", "Stop"),
    ]
    
    def __init__(self):
        super().__init__()
        self.config = ConfigManager()
        self.engine = SecurityEngine(self.config)
        self.is_scanning = False
        self.current_report: Optional[dict] = None
    
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main-container"):
            with Vertical(id="sidebar"):
                yield Static(
                    Text.from_markup(
                        "[bold red]<<<  DRAGON  >>>\n"
                        "[bold red]<<<  SHIELD  >>>\n"
                        "[dim red]Security Panel"
                    ),
                    id="logo"
                )
                yield Label("ACTIONS", classes="section-title")
                yield Button("Start Scan", id="scan-btn", classes="menu-button")
                yield Button("View Report", id="report-btn", classes="menu-button")
                yield Button("Settings", id="settings-btn", classes="menu-button")
                yield Button("Exclusions", id="exclusions-btn", classes="menu-button")
                yield Button("Clear Chat", id="clear-btn", classes="menu-button")
                yield Button("Quit", id="quit-btn", classes="menu-button")
                yield Static("", classes="status-bar", id="status")
            with Vertical(id="content"):
                yield ScrollableContainer(id="chat-container")
                yield Static(
                    f"Model: {self.config.get('model', 'N/A')} | "
                    f"Press 's' to scan | 'q' to quit",
                    classes="status-bar"
                )
        yield Footer()
    
    def on_mount(self) -> None:
        """Called when app is mounted."""
        self.add_chat_message(
            "system",
            "# DragonShield Initialized\n\n"
            "Welcome to DragonShield Security Panel.\n\n"
            "- Configure your OpenRouter API key in **Settings**\n"
            "- Set privacy **Exclusions** for sensitive paths\n"
            "- Click **Start Scan** to begin security analysis\n\n"
            "*Ensure you are running as root (sudo) for full access.*"
        )
        self.check_sudo()
    
    def check_sudo(self) -> None:
        """Check if running as root."""
        if os.geteuid() != 0:
            self.add_chat_message(
                "error",
                "**WARNING:** Not running as root!\n\n"
                "Some security checks require root access.\n"
                "Please restart with: `sudo python dragon_shield.py`"
            )
    
    def add_chat_message(self, role: str, content: str) -> None:
        """Add a message to the chat container."""
        container = self.query_one("#chat-container", ScrollableContainer)
        
        # Create styled message widget
        if role == "assistant":
            prefix = "[DRAGONSHIELD]"
        elif role == "command":
            prefix = "[EXECUTING]"
        elif role == "result":
            prefix = "[OUTPUT]"
        elif role == "error":
            prefix = "[ERROR]"
        else:
            prefix = "[SYSTEM]"
        
        message = Static(
            Markdown(f"**{prefix}**\n\n{content}"),
            classes=f"chat-message {role}"
        )
        container.mount(message)
        container.scroll_end(animate=False)
        
        # Store in history
        self.engine.chat_history.append(ChatMessage(role=role, content=content))
    
    def update_status(self, text: str) -> None:
        """Update status bar."""
        status = self.query_one("#status", Static)
        status.update(text)
    
    @on(Button.Pressed, "#scan-btn")
    def action_scan(self) -> None:
        """Start security scan."""
        if self.is_scanning:
            self.notify("Scan already in progress", severity="warning")
            return
        
        if not self.config.get("api_key"):
            self.notify("Please configure API key first", severity="error")
            self.push_screen(SettingsScreen(self.config))
            return
        
        self.run_scan()
    
    @on(Button.Pressed, "#report-btn")
    def show_report(self) -> None:
        """Show latest report."""
        if self.current_report:
            self.push_screen(ReportScreen(self.current_report))
        else:
            self.notify("No report available. Run a scan first.", severity="warning")
    
    @on(Button.Pressed, "#settings-btn")
    def action_settings(self) -> None:
        """Open settings."""
        self.push_screen(SettingsScreen(self.config))
    
    @on(Button.Pressed, "#exclusions-btn")
    def action_exclusions(self) -> None:
        """Open exclusions."""
        self.push_screen(ExclusionsScreen(self.config))
    
    @on(Button.Pressed, "#clear-btn")
    def clear_chat(self) -> None:
        """Clear chat history."""
        container = self.query_one("#chat-container", ScrollableContainer)
        container.remove_children()
        self.engine.chat_history.clear()
        self.add_chat_message("system", "Chat cleared.")
    
    @on(Button.Pressed, "#quit-btn")
    def action_quit(self) -> None:
        """Quit application."""
        self.exit()
    
    def action_stop_scan(self) -> None:
        """Stop current scan."""
        if self.is_scanning:
            self.is_scanning = False
            self.add_chat_message("system", "Scan stopped by user.")
            self.update_status("Scan stopped")
    
    @work(exclusive=True, thread=False)
    async def run_scan(self) -> None:
        """Run the security scan using LLM agent."""
        self.is_scanning = True
        self.update_status("Scanning...")
        
        self.add_chat_message(
            "system",
            "# Security Scan Started\n\n"
            f"Using model: `{self.config.get('model')}`\n\n"
            "Analyzing system security..."
        )
        
        # Build conversation
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": 
             "Please analyze the security of this Linux system. "
             "Start by gathering essential system information."}
        ]
        
        max_iterations = self.config.get("max_iterations", 10)
        iteration = 0
        
        try:
            while self.is_scanning and iteration < max_iterations:
                iteration += 1
                self.update_status(f"Iteration {iteration}/{max_iterations}")
                
                # Call LLM
                response = await self.engine.call_llm(messages)
                parsed = self.engine.parse_llm_response(response)
                
                if parsed.get("action") == "execute":
                    # Execute commands
                    commands = parsed.get("commands", [])
                    self.add_chat_message(
                        "assistant",
                        f"Requesting execution of {len(commands)} command(s)..."
                    )
                    
                    results = []
                    for cmd_info in commands:
                        cmd = cmd_info.get("cmd", "")
                        reason = cmd_info.get("reason", "")
                        
                        self.add_chat_message(
                            "command",
                            f"```bash\n{cmd}\n```\n\n*Reason: {reason}*"
                        )
                        
                        success, output = await self.engine.execute_command(cmd)
                        
                        if success:
                            self.add_chat_message(
                                "result",
                                f"```\n{output[:2000]}{'...[truncated]' if len(output) > 2000 else ''}\n```"
                            )
                            results.append(f"Command: {cmd}\nOutput:\n{output}")
                        else:
                            self.add_chat_message("error", f"Failed: {output}")
                            results.append(f"Command: {cmd}\nError: {output}")
                    
                    # Add results to conversation
                    messages.append({"role": "assistant", "content": response})
                    messages.append({
                        "role": "user", 
                        "content": "Command results:\n\n" + "\n\n---\n\n".join(results)
                    })
                
                elif parsed.get("action") == "report":
                    # Final report
                    self.current_report = parsed
                    
                    summary = parsed.get("summary", "Analysis complete")
                    findings = parsed.get("findings", [])
                    
                    report_md = f"# Security Report\n\n## Summary\n\n{summary}\n\n"
                    report_md += "## Findings\n\n"
                    
                    for f in findings:
                        severity = f.get("severity", "low").upper()
                        report_md += f"### [{severity}] {f.get('issue', 'Unknown')}\n\n"
                        report_md += f"**Fix:** {f.get('fix', 'N/A')}\n\n"
                    
                    if parsed.get("fix_commands"):
                        report_md += "## Recommended Fix Commands\n\n```bash\n"
                        report_md += "\n".join(parsed.get("fix_commands", []))
                        report_md += "\n```\n"
                    
                    self.add_chat_message("assistant", report_md)
                    self.is_scanning = False
                    self.update_status("Scan complete")
                    self.notify("Security scan complete!", severity="information")
                    break
                
                else:
                    # Plain text response
                    self.add_chat_message("assistant", parsed.get("content", response))
                    messages.append({"role": "assistant", "content": response})
                    messages.append({
                        "role": "user",
                        "content": "Please continue with your analysis or provide the final report."
                    })
            
            if iteration >= max_iterations:
                self.add_chat_message(
                    "error",
                    f"Maximum iterations ({max_iterations}) reached. "
                    "Scan incomplete. Try increasing the limit in settings."
                )
        
        except Exception as e:
            self.add_chat_message("error", f"Scan error: {str(e)}")
            self.notify(f"Scan failed: {str(e)}", severity="error")
        
        finally:
            self.is_scanning = False
            self.update_status("Ready")
    
    async def on_unmount(self) -> None:
        """Cleanup on exit."""
        await self.engine.close()


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    # Check Python version
    if sys.version_info < (3, 10):
        print("Error: Python 3.10 or higher required")
        sys.exit(1)
    
    # Run application
    app = DragonShieldApp()
    app.run()


if __name__ == "__main__":
    main()