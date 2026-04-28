# Claude Code Security Setup

Two-layer protection for sensitive files and destructive commands.

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/ladeiko/claude-code-security-setup/main/install.sh | bash
```

## Quick uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/ladeiko/claude-code-security-setup/main/uninstall.sh | bash
```

Both scripts are idempotent — safe to run multiple times. Only the rules added by the installer are affected; existing settings in `settings.json` are preserved.

## What it does

**permissions.deny** (in `~/.claude/settings.json`) — blocks Claude from reading sensitive files:

- `.env` files and variants
- SSH keys, PEM/PFX/PPK certificates
- Cloud credentials (AWS, Azure, GCloud)
- Kubernetes and Docker configs
- Database passwords (`.pgpass`, `.my.cnf`)
- Shell history (`.bash_history`, `.zsh_history`)
- Terraform state, git credentials, and more

**Hook** (`~/.claude/hooks/security-validator.py`) — blocks destructive Bash commands:

- `rm` targeting root (`/`) or home (`~`) level paths

## How it works

- The install script **merges** into your existing `~/.claude/settings.json` — it does not overwrite it
- Only missing deny rules and hooks are appended; existing settings are preserved
- A backup is saved to `~/.claude/settings.json.bak` before any changes

## Requirements

- Python 3
- Claude Code CLI

## Author

[Siarhei Ladzeika](https://github.com/ladeiko)

## Reference

Based on the original gist by [@sgasser](https://github.com/sgasser): https://gist.github.com/sgasser/efeb186bad7e68c146d6692ec05c1a57
