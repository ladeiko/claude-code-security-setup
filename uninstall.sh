#!/usr/bin/env bash
set -euo pipefail

# Uninstall script for Claude Code Security Setup
# Sources:
#   - https://gist.github.com/sgasser/efeb186bad7e68c146d6692ec05c1a57
#   - https://github.com/henryklunaris/claude-code-security

CLAUDE_DIR="$HOME/.claude"
HOOKS_DIR="$CLAUDE_DIR/hooks"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"

HOOK_FILES=(
  "$HOOKS_DIR/security-validator.py"
  "$HOOKS_DIR/prevent-force-push.py"
  "$HOOKS_DIR/prevent-env-exfil.py"
)

# Temporary backup directory (cleaned up on success)
BACKUP_DIR=$(mktemp -d)
BACKED_UP_SETTINGS=false

cleanup_on_success() {
  rm -r "$BACKUP_DIR"
}

rollback() {
  echo ""
  echo "Error: uninstall failed — rolling back..."

  if [ "$BACKED_UP_SETTINGS" = true ] && [ -f "$BACKUP_DIR/settings.json" ]; then
    cp "$BACKUP_DIR/settings.json" "$SETTINGS_FILE"
    echo "Restored $SETTINGS_FILE"
  fi

  for hook in "${HOOK_FILES[@]}"; do
    name=$(basename "$hook")
    if [ -f "$BACKUP_DIR/$name" ]; then
      cp "$BACKUP_DIR/$name" "$hook"
      chmod +x "$hook"
      echo "Restored $hook"
    fi
  done

  rm -r "$BACKUP_DIR"
  echo "Rollback complete."
  exit 1
}

trap rollback ERR

echo "Uninstalling Claude Code security setup..."

# Back up existing files
if [ -f "$SETTINGS_FILE" ]; then
  cp "$SETTINGS_FILE" "$BACKUP_DIR/settings.json"
  BACKED_UP_SETTINGS=true
fi

for hook in "${HOOK_FILES[@]}"; do
  if [ -f "$hook" ]; then
    cp "$hook" "$BACKUP_DIR/$(basename "$hook")"
  fi
done

# Remove security rules from settings.json
if [ -f "$SETTINGS_FILE" ]; then
  python3 -c "
import json

with open('$SETTINGS_FILE') as f:
    settings = json.load(f)

# --- Remove deny rules added by install ---
deny_rules = {
    # Sensitive file reads
    'Read(**/.env)',
    'Read(**/.env.*)',
    'Read(**/.ssh/id_*)',
    'Read(**/id_rsa)',
    'Read(**/id_rsa*)',
    'Read(**/id_ed25519)',
    'Read(**/id_ed25519*)',
    'Read(**/id_ecdsa*)',
    'Read(**/id_dsa*)',
    'Read(**/*.pem)',
    'Read(**/*.p12)',
    'Read(**/*.pfx)',
    'Read(**/*.ppk)',
    'Read(**/*.gpg)',
    'Read(**/*.pgp)',
    'Read(**/*.asc)',
    'Read(**/.aws/credentials)',
    'Read(**/.aws/config)',
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
    'Read(**/.mcp.json)',
    # Privilege escalation / destructive Bash
    'Bash(sudo *)',
    'Bash(su *)',
    'Bash(shred *)',
    'Bash(unlink *)',
    # Git destructive
    'Bash(git rm *)',
    'Bash(git rm -f *)',
    'Bash(git clean *)',
    'Bash(git push --force*)',
    'Bash(git reset --hard*)',
    # .env exfil shorthand
    'Bash(cat .env*)',
    'Bash(cat */.env*)',
    # Self-protection: settings.json
    'Edit(~/.claude/settings.json)',
    'Write(~/.claude/settings.json)',
    # Self-protection: hook files
    'Edit(~/.claude/hooks/security-validator.py)',
    'Write(~/.claude/hooks/security-validator.py)',
    'Edit(~/.claude/hooks/prevent-force-push.py)',
    'Write(~/.claude/hooks/prevent-force-push.py)',
    'Edit(~/.claude/hooks/prevent-env-exfil.py)',
    'Write(~/.claude/hooks/prevent-env-exfil.py)',
}

permissions = settings.get('permissions', {})
existing_deny = permissions.get('deny', [])
permissions['deny'] = [r for r in existing_deny if r not in deny_rules]

# Remove empty deny list
if not permissions['deny']:
    del permissions['deny']
# Remove empty permissions
if not permissions:
    settings.pop('permissions', None)

# --- Remove our hook entries from PreToolUse ---
managed_commands = {
    '~/.claude/hooks/security-validator.py',
    '~/.claude/hooks/prevent-force-push.py',
    '~/.claude/hooks/prevent-env-exfil.py',
}

hooks = settings.get('hooks', {})
pre_tool_use = hooks.get('PreToolUse', [])

pre_tool_use = [
    entry for entry in pre_tool_use
    if not any(
        h.get('command') in managed_commands
        for h in entry.get('hooks', [])
    )
]

if pre_tool_use:
    hooks['PreToolUse'] = pre_tool_use
else:
    hooks.pop('PreToolUse', None)

# Remove empty hooks
if not hooks:
    settings.pop('hooks', None)

with open('$SETTINGS_FILE', 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
"
  echo "Cleaned $SETTINGS_FILE"
else
  echo "No $SETTINGS_FILE found — skipping"
fi

# Remove hook files
for hook in "${HOOK_FILES[@]}"; do
  if [ -f "$hook" ]; then
    rm "$hook"
    echo "Removed $hook"
  else
    echo "No $hook found — skipping"
  fi
done

# Success — clean up temp backups
trap - ERR
cleanup_on_success

echo ""
echo "Done! Claude Code security setup uninstalled."
