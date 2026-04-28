#!/usr/bin/env bash
set -euo pipefail

# Install script for Claude Code Security Setup
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
  echo "Error: installation failed — rolling back..."

  if [ "$BACKED_UP_SETTINGS" = true ] && [ -f "$BACKUP_DIR/settings.json" ]; then
    cp "$BACKUP_DIR/settings.json" "$SETTINGS_FILE"
    echo "Restored $SETTINGS_FILE"
  elif [ "$BACKED_UP_SETTINGS" = false ] && [ -f "$SETTINGS_FILE" ]; then
    rm -f "$SETTINGS_FILE"
    echo "Removed $SETTINGS_FILE (did not exist before)"
  fi

  for hook in "${HOOK_FILES[@]}"; do
    name=$(basename "$hook")
    if [ -f "$BACKUP_DIR/$name" ]; then
      cp "$BACKUP_DIR/$name" "$hook"
      echo "Restored $hook"
    elif [ -f "$hook" ]; then
      rm -f "$hook"
      echo "Removed $hook (did not exist before)"
    fi
  done

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

for hook in "${HOOK_FILES[@]}"; do
  if [ -f "$hook" ]; then
    cp "$hook" "$BACKUP_DIR/$(basename "$hook")"
  fi
done

# Ensure settings.json exists
if [ ! -f "$SETTINGS_FILE" ]; then
  echo "{}" > "$SETTINGS_FILE"
fi

# Merge into settings.json
python3 -c "
import json

with open('$SETTINGS_FILE') as f:
    settings = json.load(f)

# --- Merge permissions.deny (append only missing) ---
deny_rules = [
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
    # .env exfil shorthand (extra layer alongside prevent-env-exfil.py)
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
]

permissions = settings.setdefault('permissions', {})
existing_deny = permissions.get('deny', [])
existing_set = set(existing_deny)
for rule in deny_rules:
    if rule not in existing_set:
        existing_deny.append(rule)
        existing_set.add(rule)
permissions['deny'] = existing_deny

# --- Merge hooks.PreToolUse (avoid duplicate entries) ---
hook_entries = [
    {
        'matcher': 'Bash',
        'hooks': [{'type': 'command', 'command': '~/.claude/hooks/security-validator.py'}]
    },
    {
        'matcher': 'Bash',
        'hooks': [{'type': 'command', 'command': '~/.claude/hooks/prevent-force-push.py'}]
    },
    {
        'matcher': 'Bash|Edit|Write|NotebookEdit|Read|Grep|Glob',
        'hooks': [{'type': 'command', 'command': '~/.claude/hooks/prevent-env-exfil.py'}]
    },
]

hooks = settings.setdefault('hooks', {})
pre_tool_use = hooks.setdefault('PreToolUse', [])

for entry in hook_entries:
    cmd = entry['hooks'][0]['command']
    already_present = any(
        any(h.get('command') == cmd for h in e.get('hooks', []))
        for e in pre_tool_use
    )
    if not already_present:
        pre_tool_use.append(entry)

with open('$SETTINGS_FILE', 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
"

echo "Updated $SETTINGS_FILE"

# Write security-validator.py hook
cat > "$HOOKS_DIR/security-validator.py" << 'HOOK_SECURITY_VALIDATOR'
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
HOOK_SECURITY_VALIDATOR

# Write prevent-force-push.py hook
# Source: https://github.com/henryklunaris/claude-code-security
cat > "$HOOKS_DIR/prevent-force-push.py" << 'HOOK_FORCE_PUSH'
#!/usr/bin/env python3
"""
PreToolUse hook to prevent dangerous git force push operations.
This hook blocks:
- git push --force
- git push -f
- git push --force-with-lease
Exit codes:
- 0: Allow the command to proceed
- 2: Block the command and show error message to Claude
"""

import json
import sys
import re

def main():
    # Read the PreToolUse input from stdin
    input_data = json.load(sys.stdin)

    # Extract tool information
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    # Only check Bash tool commands
    if tool_name != "Bash":
        sys.exit(0)

    # Check for force push patterns
    force_push_patterns = [
        r'\bgit\s+push\s+.*--force\b',
        r'\bgit\s+push\s+.*-f\b',
        r'\bgit\s+push\s+.*--force-with-lease\b'
    ]

    for pattern in force_push_patterns:
        if re.search(pattern, command):
            print("Force push is not permitted.", file=sys.stderr)
            print("", file=sys.stderr)
            print("Force pushing can overwrite history and cause data loss.", file=sys.stderr)
            print("", file=sys.stderr)
            print("If you really need to force push, please:", file=sys.stderr)
            print("1. Verify you're not on main/master branch", file=sys.stderr)
            print("2. Confirm no one else is working on this branch", file=sys.stderr)
            print("3. Use the terminal directly (not through Claude)", file=sys.stderr)
            sys.exit(2)

    sys.exit(0)

if __name__ == "__main__":
    main()
HOOK_FORCE_PUSH

# Write prevent-env-exfil.py hook
# Source: https://github.com/henryklunaris/claude-code-security
cat > "$HOOKS_DIR/prevent-env-exfil.py" << 'HOOK_ENV_EXFIL'
#!/usr/bin/env python3
"""
PreToolUse hook to prevent direct access to .env files.
Blocks attempts to exfiltrate .env contents through commands or direct file reads.
ALLOWS writing source code that uses dotenv libraries (the code itself doesn't
leak secrets -- it only reads them at runtime when the user executes it).
Exit codes:
- 0: Allow the action
- 2: Block the action
"""

import json
import sys
import re

# -----------------------------------------------------------------------
# DIRECT ACCESS patterns -- blocked in ALL contexts (Bash, Write, Edit).
# These open/read the .env file directly, which could leak secrets.
# -----------------------------------------------------------------------
DIRECT_ACCESS_PATTERNS = [
      # === Language-level direct file reads of .env ===
      r"""open\s*\(\s*['"]\.env""",
      r"""readFile.*['"]\.env""",
      r"""readFileSync.*['"]\.env""",
      r"""fs\.read.*['"]\.env""",
      r"""pathlib.*\.env""",
      r"""Path\s*\(\s*['"]\.env""",

      # === Shell commands that read files ===
      r"""\bcat\s+.*\.env""",
      r"""\bless\s+.*\.env""",
      r"""\bmore\s+.*\.env""",
      r"""\bhead\s+.*\.env""",
      r"""\btail\s+.*\.env""",
      r"""\bgrep\s+.*\.env""",
      r"""\bawk\s+.*\.env""",
      r"""\bsed\s+.*\.env""",
      r"""\bsort\s+.*\.env""",
      r"""\bstrings\s+.*\.env""",
      r"""\bxxd\s+.*\.env""",
      r"""\bbase64\s+.*\.env""",
      r"""\bdd\s+.*if=.*\.env""",
      r"""\btee\s+.*\.env""",
      r"""<\s*\.env""",

      # === Editors ===
      r"""\bvim?\s+.*\.env""",
      r"""\bnano\s+.*\.env""",
      r"""\bemacs\s+.*\.env""",

      # === Source / eval ===
      r"""\bsource\s+.*\.env""",
      r"""\.\s+\.env""",
      r"""\beval\s+.*\.env""",

      # === Inline script tricks ===
      r"""python[23]?\s+-c\s+.*env""",
      r"""node\s+-e\s+.*env""",
      r"""ruby\s+-e\s+.*env""",
      r"""perl\s+-e\s+.*env""",
      r"""php\s+-r\s+.*env""",
      r"""\bpython.*['"]\.env""",
      r"""\bnode.*['"]\.env""",
      r"""\bruby.*['"]\.env""",
      r"""\bperl.*['"]\.env""",
      r"""\bphp.*['"]\.env""",

      # === Copy / move / link ===
      r"""\bcp\s+.*\.env""",
      r"""\bmv\s+.*\.env""",
      r"""\bln\s+.*\.env""",
      r"""\brsync\s+.*\.env""",

      # === Archive / compress ===
      r"""\btar\s+.*\.env""",
      r"""\bzip\s+.*\.env""",
      r"""\bgzip\s+.*\.env""",

      # === Network exfiltration ===
      r"""curl.*\.env""",
      r"""wget.*\.env""",
      r"""\bnc\s+.*\.env""",
      r"""\bnetcat\s+.*\.env""",

      # === Find + exec patterns ===
      r"""\bfind\s+.*\.env""",
      r"""\bxargs\s+.*\.env""",
      r"""\blocate\s+.*\.env""",

      # === Git exposure ===
      r"""\bgit\s+add\s+.*\.env""",
      r"""\bgit\s+show.*\.env""",
      r"""\bgit\s+diff.*\.env""",

      # === Glob / wildcard tricks ===
      r"""\bcat\s+\.e\*""",
      r"""\bcat\s+\.en.""",
      r"""\bcat\s+\.\*env""",

      # === Environment dumping ===
      r"""\bprintenv\b""",
      r"""\b/proc/self/environ""",
      r"""\b/proc/.*/environ""",

  ]

# -----------------------------------------------------------------------
# BASH-ONLY patterns -- only blocked when run as shell commands.
# These are safe in written source code (scripts, docs, configs) because
# they don't execute until the user runs them. Includes dotenv library
# imports and .env filename references that appear in normal code/docs.
# -----------------------------------------------------------------------
BASH_ONLY_PATTERNS = [
      # === dotenv library usage ===
      r"""load_dotenv""",
      r"""dotenv\.config""",
      r"""dotenv\.load""",
      r"""dotenv\.parse""",
      r"""require\s*\(\s*['"]dotenv""",
      r"""import.*dotenv""",
      r"""from\s+dotenv""",

      # === .env filename references (common in docs, configs, code) ===
      r"""['"]\.env['"]""",
      r"""\.env\.local""",
      r"""\.env\.prod""",
      r"""\.env\.dev""",
      r"""\.env\.staging""",
      r"""\.env\.production""",
      r"""\.env\.development""",
  ]


def check_patterns(text, patterns):
    """Check if text matches any of the given patterns."""
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return pattern
    return None


def main():
    input_data = json.load(sys.stdin)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    text_to_check = ""

    if tool_name == "Bash":
        text_to_check = tool_input.get("command", "")
    elif tool_name in ("Edit", "Write"):
        # Check both new content being written and the file path
        text_to_check = tool_input.get("content", "")
        text_to_check += "\n" + tool_input.get("new_string", "")
    elif tool_name == "NotebookEdit":
        text_to_check = tool_input.get("new_source", "")
    elif tool_name in ("Read", "Grep", "Glob"):
        text_to_check = json.dumps(tool_input)
    else:
        sys.exit(0)

    # Always check direct access patterns (all tools)
    match = check_patterns(text_to_check, DIRECT_ACCESS_PATTERNS)
    if match:
        print("Blocked: direct .env file access is not allowed.", file=sys.stderr)
        print("", file=sys.stderr)
        print("This hook prevents reading, copying, or directly accessing", file=sys.stderr)
        print(".env files to protect secrets from exposure.", file=sys.stderr)
        sys.exit(2)

    # Only check bash-only patterns for Bash (immediate execution)
    if tool_name == "Bash":
        match = check_patterns(text_to_check, BASH_ONLY_PATTERNS)
        if match:
            print("Blocked: running dotenv in a shell command is not allowed.", file=sys.stderr)
            print("", file=sys.stderr)
            print("You can write code that uses dotenv, but Claude cannot", file=sys.stderr)
            print("execute it directly. Run the script yourself with:", file=sys.stderr)
            print("  ! python3 your_script.py", file=sys.stderr)
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
HOOK_ENV_EXFIL

for hook in "${HOOK_FILES[@]}"; do
  chmod +x "$hook"
  echo "Wrote $hook (executable)"
done

# Success — clean up temp backups
trap - ERR
cleanup_on_success

echo ""
echo "Done! Claude Code security setup installed:"
echo "  - Sensitive file read blocking (permissions.deny)"
echo "  - Destructive command blocking (security-validator.py + permissions.deny)"
echo "  - Git force push prevention (prevent-force-push.py)"
echo "  - .env exfiltration prevention (prevent-env-exfil.py)"
