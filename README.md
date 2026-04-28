# Claude Code Security Setup

Layered protection for sensitive files, secret exfiltration, and destructive commands.

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

**permissions.deny** (in `~/.claude/settings.json`) — blocks Claude at the permission layer:

- `.env` files and variants, plus `cat .env*` shortcuts
- SSH keys (`id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`), PEM/PFX/PPK certificates
- Cloud credentials (AWS credentials & config, Azure, GCloud)
- Kubernetes, Docker, and MCP configs
- Database passwords (`.pgpass`, `.my.cnf`)
- Shell history (`.bash_history`, `.zsh_history`)
- Terraform state, git credentials, and more
- Privilege escalation (`sudo`, `su`)
- Destructive commands (`shred`, `unlink`, `git rm`, `git clean`, `git push --force*`, `git reset --hard*`)
- Self-protection: prevents Claude from editing the hooks or `~/.claude/settings.json`, and from rewriting them via Bash (`>`, `tee`, `cp`, `rm`, `chmod`, …)

**Hooks** (in `~/.claude/hooks/`) — catch what permission rules miss:

- `security-validator.py` — blocks destructive commands: `rm` against root / home / `$HOME` / system dirs (`/etc`, `/var`, `/usr`, `/bin`, `/sbin`, `/lib`, `/opt`, `/boot`, `/root`, `/private`, `/System`, `/Library`), bare `rm .` / `rm *`, `find / -delete` / `find / -exec rm`, `rsync --delete /`, and recursive `chmod`/`chown` against the same paths
- `prevent-force-push.py` — blocks `git push --force`, `-f`, `--force-with-lease`, and `+refspec` (`git push origin +main:main`); normalizes `git -c key=val push …` so config flags can't disguise the push
- `prevent-env-exfil.py` — blocks 80+ `.env` exfiltration patterns (direct reads, copies, archives, network exfil, environment dumping, inline script tricks, `subprocess` argv-style `['cat', '.env']`, hash/metadata leaks via `md5sum`/`stat`/`wc`, etc.) while still allowing Claude to write source code that uses `load_dotenv()` at runtime
- `prevent-claude-tamper.py` — blocks Bash-level writes, deletes, and `chmod` against anything under `~/.claude/`, so the hooks and settings can't be disabled with a shell redirect

## How `.env` access works

The env-exfil hook splits patterns into two layers:

1. **Direct access** (blocked everywhere) — `cat .env`, `open('.env')`, `cp .env`, `source .env`, `curl ... .env`, `printenv`, `python3 -c '...'` with env references, etc.
2. **Bash-only** (allowed in source code, blocked in shell) — `load_dotenv`, `import dotenv`, `dotenv.config()`, and `.env` filename string references.

This lets Claude write a script using `load_dotenv()` and run it as `python3 script.py` — the secrets stay in the file and load at runtime, but Claude can't read them directly.

## How it works

- The install script **merges** into your existing `~/.claude/settings.json` — it does not overwrite it
- Only missing deny rules and hooks are appended; existing settings are preserved
- The uninstall script removes only what the installer added
- A backup of `settings.json` and any pre-existing hook files is held during install/uninstall, and restored automatically on failure

## Requirements

- Python 3
- Claude Code CLI

## Author

[Siarhei Ladzeika](https://github.com/ladeiko)

## References

- Original `permissions.deny` gist by [@sgasser](https://github.com/sgasser): https://gist.github.com/sgasser/efeb186bad7e68c146d6692ec05c1a57
- `prevent-force-push.py` and `prevent-env-exfil.py` hooks by [@henryklunaris](https://github.com/henryklunaris): https://github.com/henryklunaris/claude-code-security

## License

[MIT](LICENSE)
