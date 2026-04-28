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
  "$HOOKS_DIR/prevent-claude-tamper.py"
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
    'Bash(/usr/bin/sudo *)',
    'Bash(/bin/sudo *)',
    'Bash(su *)',
    'Bash(/usr/bin/su *)',
    'Bash(/bin/su *)',
    'Bash(shred *)',
    'Bash(unlink *)',
    # Git destructive
    'Bash(git rm *)',
    'Bash(git rm -f *)',
    'Bash(git clean *)',
    'Bash(git push --force*)',
    'Bash(git reset --hard*)',
    # git -C <dir> bypasses (covers `git -C /tmp rm -rf *`, etc.)
    'Bash(git -C * rm *)',
    'Bash(git -C * clean *)',
    'Bash(git -C * push --force*)',
    'Bash(git -C * reset --hard*)',
    # +refspec force pushes (covers `git push origin +main:main`)
    'Bash(git push * +*:*)',
    'Bash(git push +*:*)',
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
    'Edit(~/.claude/hooks/prevent-claude-tamper.py)',
    'Write(~/.claude/hooks/prevent-claude-tamper.py)',
    # Self-protection: Bash-level tampering with ~/.claude/
    # (prevent-claude-tamper.py is the comprehensive backstop; these
    # deny rules give a fast-fail at the permission layer.)
    'Bash(rm ~/.claude/*)',
    'Bash(rm -rf ~/.claude*)',
    'Bash(chmod * ~/.claude/*)',
    'Bash(tee ~/.claude/*)',
    'Bash(* > ~/.claude/*)',
    'Bash(* >> ~/.claude/*)',
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
        'matcher': 'Bash',
        'hooks': [{'type': 'command', 'command': '~/.claude/hooks/prevent-claude-tamper.py'}]
    },
    {
        'matcher': 'Bash|Edit|MultiEdit|Write|NotebookEdit|Read|Grep|Glob',
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
Blocks destructive commands like 'rm -rf' and recursive chmod/chown
against root, home, or system directories. For file access blocking,
use permissions.deny in settings.json instead.
"""

import json
import sys
import re

# Known-dangerous system directory roots.
DANGEROUS_SYS = r"(?:/etc|/var|/usr|/bin|/sbin|/lib|/opt|/boot|/root|/private|/System|/Library)"

CHECKS = [
    # rm against root, home, $HOME, or system dirs
    (
        rf"\brm\s+(?:-[a-zA-Z]*\s+)*(?:/$|/\s|/\*|~/|~\s|~$|\$HOME\b|\$\{{HOME\}}|{DANGEROUS_SYS}\b)",
        "rm against root/home/system directories is blocked.",
    ),
    # rm of a bare '.' or '*' argument — almost always catastrophic in some cwd
    (
        r"\brm\s+(?:[^\n]*?\s)?(?:\.|\*)(?:\s|$|;|&|\|)",
        "rm of bare '.' or '*' is blocked. Use explicit paths.",
    ),
    # find -delete or -exec rm rooted at /, ~, or a system dir
    (
        rf"\bfind\s+(?:/(?:\s|$)|~(?:/|\s|$)|{DANGEROUS_SYS}\b)[^\n]*?(?:-delete\b|-exec\s+(?:rm|unlink)\b)",
        "find -delete or -exec rm against root/home/system is blocked.",
    ),
    # rsync --delete with a / or ~ destination
    (
        r"\brsync\b[^\n]*?--delete\b[^\n]*?\s(?:/(?:\s|$)|~(?:/|\s|$))",
        "rsync --delete against root/home is blocked.",
    ),
    # Recursive chmod/chown against root/home/system
    (
        rf"\b(?:chmod|chown)\s+(?:-\w*R\w*|-R|--recursive)\b[^\n]*?\s(?:/(?:\s|$)|~(?:/|\s|$)|{DANGEROUS_SYS}\b)",
        "recursive chmod/chown against root/home/system is blocked.",
    ),
]


def check_bash_command(command: str) -> tuple[bool, str]:
    """Return (is_allowed, error_message) for a Bash command."""
    for pattern, message in CHECKS:
        if re.search(pattern, command):
            return False, message
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
    # Read the PreToolUse input from stdin (fail-closed on parse errors)
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Hook input invalid: {e}", file=sys.stderr)
        sys.exit(2)

    # Extract tool information
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    # Only check Bash tool commands
    if tool_name != "Bash":
        sys.exit(0)

    # Normalize 'git -c key=value -c k=v push ...' down to 'git push ...'
    # so per-invocation config flags can't hide the push command.
    normalized = re.sub(r"\bgit\s+(?:-c\s+\S+\s+)+", "git ", command)

    # Check for force push patterns
    force_push_patterns = [
        r'\bgit\s+push\s+.*--force\b',
        r'\bgit\s+push\s+.*-f\b',
        r'\bgit\s+push\s+.*--force-with-lease\b',
        # +refspec (e.g. 'git push origin +main:main') forces a non-FF push.
        r'\bgit\s+push\s+(?:\S+\s+)*\+\S+:',
    ]

    for pattern in force_push_patterns:
        if re.search(pattern, normalized):
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

      # === Additional readers / metadata leaks ===
      r"""\bod\s+.*\.env""",
      r"""\bhexdump\s+.*\.env""",
      r"""\bpaste\s+.*\.env""",
      r"""\bcut\s+.*\.env""",
      r"""\bcolumn\s+.*\.env""",
      r"""\bpr\s+.*\.env""",
      r"""\bjq\s+.*\.env""",
      r"""\byq\s+.*\.env""",
      r"""\bnl\s+.*\.env""",
      r"""\bed\s+.*\.env""",
      r"""\bex\s+.*\.env""",
      r"""\bview\s+.*\.env""",
      r"""\bwc\s+.*\.env""",
      r"""\bdu\s+.*\.env""",
      r"""\bstat\s+.*\.env""",
      r"""\bmd5sum\s+.*\.env""",
      r"""\bsha\d+sum\s+.*\.env""",
      r"""\bopenssl\s+.*\.env""",
      r"""\bmapfile\s+.*\.env""",
      r"""\breadarray\s+.*\.env""",
      r"""\blink\s+.*\.env""",

      # === Additional compression / archive ===
      r"""\bbzip2\s+.*\.env""",
      r"""\bxz\s+.*\.env""",
      r"""\blzma\s+.*\.env""",
      r"""\b7z\s+.*\.env""",
      r"""\bzstd\s+.*\.env""",

      # === subprocess argv-style: ['cat', '.env'] / ['/bin/cat', '.env'] ===
      r"""\[\s*['"](?:/[^'"\s]+/)?(?:cat|head|tail|less|more|grep|awk|sed|od|hexdump|xxd|wc|stat|md5sum)['"][^\]]*?['"]\.env""",

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
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Hook input invalid: {e}", file=sys.stderr)
        sys.exit(2)

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    text_to_check = ""

    if tool_name == "Bash":
        text_to_check = tool_input.get("command", "")
    elif tool_name in ("Edit", "Write"):
        # Check both new content being written and the file path
        text_to_check = tool_input.get("content", "")
        text_to_check += "\n" + tool_input.get("new_string", "")
    elif tool_name == "MultiEdit":
        # MultiEdit applies a list of {old_string, new_string} edits to a file.
        # Scan every new_string (and any 'content' field if present).
        text_to_check = tool_input.get("content", "")
        for edit in tool_input.get("edits", []) or []:
            text_to_check += "\n" + edit.get("new_string", "")
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

# Write prevent-claude-tamper.py hook
# Catches Bash-level attempts to overwrite, delete, or chmod files under
# ~/.claude/ — the deny rules cover Edit/Write tools, but Bash redirection
# (echo > ..., tee, sed -i, cp, rm, chmod, python -c "open(...,'w')", etc.)
# is a separate path that this hook closes.
cat > "$HOOKS_DIR/prevent-claude-tamper.py" << 'HOOK_TAMPER'
#!/usr/bin/env python3
"""
PreToolUse hook to prevent tampering with ~/.claude/ via Bash.

Without this, Edit/Write deny rules on the hooks and settings.json can
be bypassed by issuing the equivalent operation through a shell command
(redirect, tee, cp, mv, sed -i, python -c, rm, chmod, etc.).

Exit codes:
- 0: Allow the action
- 2: Block the action
"""

import json
import sys
import re

# Matches any reference to ~/.claude/ or .claude/ in any reasonable form.
CLAUDE_PATH = r"""(?:~/|\$HOME/|\$\{HOME\}/|/Users/[^/\s'"]+/|/home/[^/\s'"]+/)?\.claude/"""

TAMPER_PATTERNS = [
    # Output redirection ( > or >> ) into .claude/
    rf">>?\s*['\"]?{CLAUDE_PATH}",
    # tee writes
    rf"\btee\b\s+(?:-\w+\s+)*['\"]?{CLAUDE_PATH}",
    # File copy / move / link / install / rsync touching .claude/
    rf"\b(?:cp|mv|install|rsync|ln)\b[^\n]*?{CLAUDE_PATH}",
    # In-place edit with sed/perl
    rf"\bsed\b\s+(?:-\w+\s+)*-i\b[^\n]*{CLAUDE_PATH}",
    rf"\bperl\b\s+(?:-\w+\s+)*-i\b[^\n]*{CLAUDE_PATH}",
    # Inline scripts that open .claude/* for writing
    rf"(?:python[23]?|perl|ruby|node|php)[^\n]*open\s*\([^)]*{CLAUDE_PATH}",
    rf"(?:python[23]?|perl|ruby|node|php)[^\n]*[wW]riteFile[^\n]*{CLAUDE_PATH}",
    # Removal / truncation / overwrite
    rf"\brm\b[^\n]*{CLAUDE_PATH}",
    rf"\btruncate\b[^\n]*{CLAUDE_PATH}",
    rf"\bdd\b[^\n]*\bof=[^\s]*{CLAUDE_PATH}",
    # Make hooks non-executable / writable / change owner
    rf"\bchmod\b[^\n]*{CLAUDE_PATH}",
    rf"\bchown\b[^\n]*{CLAUDE_PATH}",
]


def main():
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"Hook input invalid: {e}", file=sys.stderr)
        sys.exit(2)

    if input_data.get("tool_name") != "Bash":
        sys.exit(0)

    command = input_data.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    for pattern in TAMPER_PATTERNS:
        if re.search(pattern, command):
            print("Blocked: modification of ~/.claude/ via Bash is not allowed.", file=sys.stderr)
            print("", file=sys.stderr)
            print("This protects the hook files and settings from being", file=sys.stderr)
            print("disabled or rewritten through shell commands. If you", file=sys.stderr)
            print("really need to change them, run the command yourself", file=sys.stderr)
            print("with the ! prefix.", file=sys.stderr)
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
HOOK_TAMPER

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
echo "  - ~/.claude/ tamper prevention (prevent-claude-tamper.py)"
