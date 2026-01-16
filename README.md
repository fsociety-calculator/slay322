# DragonShield Scanner

![alt text](https://raw.githubusercontent.com/fsociety-calculator/screenshots/refs/heads/main/Screenshot%202026-01-16%20213243.png)

## Process
![alt text](https://raw.githubusercontent.com/fsociety-calculator/screenshots/refs/heads/main/Screenshot%202026-01-16%20215022.png)


# DragonShield Installation Guide

Linux security analyzer using AI. Requires Python 3.10+ and an OpenRouter API key.

## Debian / Ubuntu

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Fedora

```bash
sudo dnf install python3 python3-pip
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Arch Linux

```bash
sudo pacman -S python python-pip
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## openSUSE

```bash
sudo zypper install python3 python3-pip python3-venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Alpine

```bash
apk add python3 py3-pip
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running

```bash
source venv/bin/activate
python dragon_shield.py
```

For full scan capabilities run as root:

```bash
sudo venv/bin/python dragon_shield.py
```

## Configuration

1. Launch the program
2. Press `2` or select "System Configuration"
3. Enter your OpenRouter API key (get one at https://openrouter.ai) or configure your own local/remote model
4. Select preferred model
5. Save

Config file location: `~/.config/dragonshield/config.json`

## Controls

| Key | Action |
|-----|--------|
| 1 | Start scan |
| 2 | Settings |
| 3 | Exclusions |
| 4 | Clear log |
| 5 / q | Quit |
| Escape | Stop scan |

## Notes

- Running without root limits what security checks can be performed
- Windows paths under WSL are excluded by default
- Sensitive file patterns are automatically redacted from output

## Result
![alt text](https://raw.githubusercontent.com/fsociety-calculator/screenshots/refs/heads/main/Screenshot%202026-01-16%20213127.png)
