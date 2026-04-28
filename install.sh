#!/usr/bin/env bash
set -euo pipefail

# Install script for Claude Code Security Setup
# Source: https://gist.github.com/sgasser/efeb186bad7e68c146d6692ec05c1a57

CLAUDE_DIR="$HOME/.claude"
HOOKS_DIR="$CLAUDE_DIR/hooks"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
HOOK_FILE="$HOOKS_DIR/security-validator.py"

# Temporary backup directory (cleaned up on success)
BACKUP_DIR=$(mktemp -d)
BACKED_UP_SETTINGS=false
BACKED_UP_HOOK=false

cleanup_on_success() {
  rm -r "$BACKUP_DIR"
}

rollback() {
  echo ""
  echo "Error: installation failed — rolling back..."

  if [ "$BACKED_UP_SETTINGS" = true ] && [ -f "$BACKUP_DIR/settings.json" ]; then
    cp "$BACKUP_DIR/settings.json" "$SETTINGS_FILE"
    echo "Restored $SETTINGS_FILE"
  elif [ "$BACKED_UP_SETTINGS" = false ] && [ -f "$SETTINGS_FILE" ]; then
    # settings.json didn't exist before, remove it
    rm -f "$SETTINGS_FILE"
    echo "Removed $SETTINGS_FILE (did not exist before)"
  fi

  if [ "$BACKED_UP_HOOK" = true ] && [ -f "$BACKUP_DIR/security-validator.py" ]; then
    cp "$BACKUP_DIR/security-validator.py" "$HOOK_FILE"
    echo "Restored $HOOK_FILE"
  elif [ "$BACKED_UP_HOOK" = false ] && [ -f "$HOOK_FILE" ]; then
    rm -f "$HOOK_FILE"
    echo "Removed $HOOK_FILE (did not exist before)"
  fi

  rm -r "$BACKUP_DIR"
  echo "Rollback complete."
  exit 1
}

trap rollback ERR

echo "Installing Claude Code security setup..."

# Create directories
mkdir -p "$HOOKS_DIR"

# Back up existing files
if [ -f "$SETTINGS_FILE" ]; then
  cp "$SETTINGS_FILE" "$BACKUP_DIR/settings.json"
  BACKED_UP_SETTINGS=true
fi

if [ -f "$HOOK_FILE" ]; then
  cp "$HOOK_FILE" "$BACKUP_DIR/security-validator.py"
  BACKED_UP_HOOK=true
fi

# Ensure settings.json exists
if [ ! -f "$SETTINGS_FILE" ]; then
  echo "{}" > "$SETTINGS_FILE"
fi

# Merge into settings.json
python3 -c "
import json, sys

with open('$SETTINGS_FILE') as f:
    settings = json.load(f)

# --- Merge permissions.deny (append only missing) ---
deny_rules = [
    'Read(**/.env)',
    'Read(**/.env.*)',
    'Read(**/.ssh/id_*)',
    'Read(**/id_rsa)',
    'Read(**/id_ed25519)',
    'Read(**/*.pem)',
    'Read(**/*.p12)',
    'Read(**/*.pfx)',
    'Read(**/*.ppk)',
    'Read(**/*.gpg)',
    'Read(**/*.pgp)',
    'Read(**/*.asc)',
    'Read(**/.aws/credentials)',
    'Read(**/.azure/**)',
    'Read(**/.config/gcloud/**)',
    'Read(**/.kube/config)',
    'Read(**/*vault_pass*)',
    'Read(**/secrets.yml)',
    'Read(**/secrets.yaml)',
    'Read(**/secrets.json)',
    'Read(**/credentials.json)',
    'Read(**/.htpasswd)',
    'Read(**/.netrc)',
    'Read(**/.npmrc)',
    'Read(**/.pypirc)',
    'Read(**/application.properties)',
    'Read(**/appsettings.json)',
    'Read(**/*.tfstate)',
    'Read(**/.git/config)',
    'Read(**/.git-credentials)',
    'Read(**/.bash_history)',
    'Read(**/.zsh_history)',
    'Read(**/.pgpass)',
    'Read(**/.my.cnf)',
    'Read(**/.docker/config.json)',
    'Read(**/*.jks)',
    'Read(**/*.keystore)',
]

permissions = settings.setdefault('permissions', {})
existing_deny = permissions.get('deny', [])
existing_set = set(existing_deny)
for rule in deny_rules:
    if rule not in existing_set:
        existing_deny.append(rule)
permissions['deny'] = existing_deny

# --- Merge hooks.PreToolUse (avoid duplicate entry) ---
hook_entry = {
    'matcher': 'Bash',
    'hooks': [
        {
            'type': 'command',
            'command': '~/.claude/hooks/security-validator.py'
        }
    ]
}

hooks = settings.setdefault('hooks', {})
pre_tool_use = hooks.get('PreToolUse', [])

already_present = any(
    any(
        h.get('command') == '~/.claude/hooks/security-validator.py'
        for h in entry.get('hooks', [])
    )
    for entry in pre_tool_use
)

if not already_present:
    pre_tool_use.append(hook_entry)

hooks['PreToolUse'] = pre_tool_use

with open('$SETTINGS_FILE', 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
"

echo "Updated $SETTINGS_FILE"

# Write security-validator.py hook
cat > "$HOOK_FILE" << 'HOOK'
#!/usr/bin/env python3

"""
Security validator hook for Claude Code.
Blocks destructive commands like 'rm -rf'.
For file access blocking, use permissions.deny in settings.json instead.
"""

import json
import sys
import re

def check_bash_command(command: str) -> tuple[bool, str]:
    """
    Validate bash commands for dangerous patterns.
    Returns: (is_allowed, error_message)
    """
    # Block rm targeting root (/) or home (~) directly
    if re.search(r'\brm\s+(-[a-zA-Z]*\s+)*(/$|/\s|/\*|~/|~\s|~$)', command):
        return False, "rm at root/home level is blocked. Use explicit paths in safe locations."

    return True, ""

def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Only validate Bash commands
    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    is_allowed, error_msg = check_bash_command(command)

    if not is_allowed:
        # Exit code 2 = block with error message
        print(f"SECURITY BLOCK: {error_msg}", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)

if __name__ == "__main__":
    main()
HOOK

chmod +x "$HOOK_FILE"
echo "Wrote $HOOK_FILE (executable)"

# Success — clean up temp backups
trap - ERR
cleanup_on_success

echo ""
echo "Done! Claude Code security setup installed:"
echo "  - Sensitive file read blocking (permissions.deny)"
echo "  - Destructive command blocking (security-validator.py hook)"
