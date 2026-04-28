#!/usr/bin/env bash
set -euo pipefail

# Uninstall script for Claude Code Security Setup
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
  echo "Error: uninstall failed — rolling back..."

  if [ "$BACKED_UP_SETTINGS" = true ] && [ -f "$BACKUP_DIR/settings.json" ]; then
    cp "$BACKUP_DIR/settings.json" "$SETTINGS_FILE"
    echo "Restored $SETTINGS_FILE"
  fi

  if [ "$BACKED_UP_HOOK" = true ] && [ -f "$BACKUP_DIR/security-validator.py" ]; then
    cp "$BACKUP_DIR/security-validator.py" "$HOOK_FILE"
    chmod +x "$HOOK_FILE"
    echo "Restored $HOOK_FILE"
  fi

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

if [ -f "$HOOK_FILE" ]; then
  cp "$HOOK_FILE" "$BACKUP_DIR/security-validator.py"
  BACKED_UP_HOOK=true
fi

# Remove security rules from settings.json
if [ -f "$SETTINGS_FILE" ]; then
  python3 -c "
import json

with open('$SETTINGS_FILE') as f:
    settings = json.load(f)

# --- Remove deny rules added by install ---
deny_rules = {
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
}

permissions = settings.get('permissions', {})
existing_deny = permissions.get('deny', [])
permissions['deny'] = [r for r in existing_deny if r not in deny_rules]

# Remove empty deny list
if not permissions['deny']:
    del permissions['deny']
# Remove empty permissions
if not permissions:
    del settings['permissions']

# --- Remove security-validator hook from PreToolUse ---
hooks = settings.get('hooks', {})
pre_tool_use = hooks.get('PreToolUse', [])

pre_tool_use = [
    entry for entry in pre_tool_use
    if not any(
        h.get('command') == '~/.claude/hooks/security-validator.py'
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

# Remove hook file
if [ -f "$HOOK_FILE" ]; then
  rm "$HOOK_FILE"
  echo "Removed $HOOK_FILE"
else
  echo "No $HOOK_FILE found — skipping"
fi

# Success — clean up temp backups
trap - ERR
cleanup_on_success

echo ""
echo "Done! Claude Code security setup uninstalled."
