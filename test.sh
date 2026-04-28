#!/usr/bin/env bash
set -uo pipefail

# Unit tests for install.sh and uninstall.sh
# Uses a fake HOME in a temp directory — never touches real files.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PASSED=0
FAILED=0

# --- Helpers ---

setup() {
  export FAKE_HOME=$(mktemp -d)
  export HOME="$FAKE_HOME"
}

teardown() {
  rm -r "$FAKE_HOME"
}

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    echo "  PASS: $desc"
    ((PASSED++))
  else
    echo "  FAIL: $desc"
    echo "    expected: $expected"
    echo "    actual:   $actual"
    ((FAILED++))
  fi
}

assert_file_exists() {
  local desc="$1" path="$2"
  if [ -f "$path" ]; then
    echo "  PASS: $desc"
    ((PASSED++))
  else
    echo "  FAIL: $desc — file not found: $path"
    ((FAILED++))
  fi
}

assert_file_not_exists() {
  local desc="$1" path="$2"
  if [ ! -f "$path" ]; then
    echo "  PASS: $desc"
    ((PASSED++))
  else
    echo "  FAIL: $desc — file should not exist: $path"
    ((FAILED++))
  fi
}

assert_file_executable() {
  local desc="$1" path="$2"
  if [ -x "$path" ]; then
    echo "  PASS: $desc"
    ((PASSED++))
  else
    echo "  FAIL: $desc — file not executable: $path"
    ((FAILED++))
  fi
}

json_get() {
  python3 -c "import json; data=json.load(open('$1')); print(json.dumps($2))"
}

json_len() {
  python3 -c "import json; data=json.load(open('$1')); print(len($2))"
}

json_contains() {
  python3 -c "
import json
data = json.load(open('$1'))
items = $2
print('true' if $3 in items else 'false')
"
}

# --- Tests ---

echo "=== Test 1: Fresh install (no existing settings) ==="
setup
  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1

  assert_file_exists "settings.json created" "$FAKE_HOME/.claude/settings.json"
  assert_file_exists "hook file created" "$FAKE_HOME/.claude/hooks/security-validator.py"
  assert_file_executable "hook file is executable" "$FAKE_HOME/.claude/hooks/security-validator.py"

  deny_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['permissions']['deny']")
  assert_eq "deny list has 37 rules" "37" "$deny_count"

  hook_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['hooks']['PreToolUse']")
  assert_eq "PreToolUse has 1 entry" "1" "$hook_count"
teardown

echo ""
echo "=== Test 2: Idempotency (run install twice) ==="
setup
  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1
  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1

  deny_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['permissions']['deny']")
  assert_eq "deny list still 37 after second run" "37" "$deny_count"

  hook_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['hooks']['PreToolUse']")
  assert_eq "PreToolUse still 1 entry after second run" "1" "$hook_count"
teardown

echo ""
echo "=== Test 3: Install preserves existing settings ==="
setup
  mkdir -p "$FAKE_HOME/.claude"
  cat > "$FAKE_HOME/.claude/settings.json" << 'EOF'
{
  "permissions": {
    "deny": ["Bash(rm *)"],
    "allow": ["Read(**/*.md)"]
  },
  "customKey": "customValue"
}
EOF

  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1

  # Existing deny rule preserved
  has_existing=$(json_contains "$FAKE_HOME/.claude/settings.json" "data['permissions']['deny']" "'Bash(rm *)'")
  assert_eq "existing deny rule preserved" "true" "$has_existing"

  # Existing allow key preserved
  allow=$(json_get "$FAKE_HOME/.claude/settings.json" "data['permissions']['allow']")
  assert_eq "existing allow key preserved" '["Read(**/*.md)"]' "$allow"

  # Custom key preserved
  custom=$(json_get "$FAKE_HOME/.claude/settings.json" "data['customKey']")
  assert_eq "custom key preserved" '"customValue"' "$custom"

  deny_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['permissions']['deny']")
  assert_eq "deny list has 38 rules (1 existing + 37 new)" "38" "$deny_count"
teardown

echo ""
echo "=== Test 4: Install preserves existing hooks ==="
setup
  mkdir -p "$FAKE_HOME/.claude"
  cat > "$FAKE_HOME/.claude/settings.json" << 'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [{"type": "command", "command": "my-custom-hook.sh"}]
      }
    ]
  }
}
EOF

  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1

  hook_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['hooks']['PreToolUse']")
  assert_eq "PreToolUse has 2 entries (1 existing + 1 new)" "2" "$hook_count"

  # Existing hook preserved
  existing_cmd=$(json_get "$FAKE_HOME/.claude/settings.json" "data['hooks']['PreToolUse'][0]['hooks'][0]['command']")
  assert_eq "existing hook command preserved" '"my-custom-hook.sh"' "$existing_cmd"
teardown

echo ""
echo "=== Test 5: Uninstall removes security rules ==="
setup
  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1
  bash "$SCRIPT_DIR/uninstall.sh" > /dev/null 2>&1

  assert_file_not_exists "hook file removed" "$FAKE_HOME/.claude/hooks/security-validator.py"

  # settings.json should be essentially empty (clean keys removed)
  has_permissions=$(python3 -c "import json; data=json.load(open('$FAKE_HOME/.claude/settings.json')); print('permissions' in data)")
  assert_eq "permissions key removed (was empty)" "False" "$has_permissions"

  has_hooks=$(python3 -c "import json; data=json.load(open('$FAKE_HOME/.claude/settings.json')); print('hooks' in data)")
  assert_eq "hooks key removed (was empty)" "False" "$has_hooks"
teardown

echo ""
echo "=== Test 6: Uninstall preserves other settings ==="
setup
  mkdir -p "$FAKE_HOME/.claude"
  cat > "$FAKE_HOME/.claude/settings.json" << 'EOF'
{
  "permissions": {
    "deny": ["Bash(rm *)"],
    "allow": ["Read(**/*.md)"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [{"type": "command", "command": "my-custom-hook.sh"}]
      }
    ]
  },
  "customKey": "customValue"
}
EOF

  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1
  bash "$SCRIPT_DIR/uninstall.sh" > /dev/null 2>&1

  # User's own deny rule preserved
  has_existing=$(json_contains "$FAKE_HOME/.claude/settings.json" "data['permissions']['deny']" "'Bash(rm *)'")
  assert_eq "user deny rule preserved after uninstall" "true" "$has_existing"

  deny_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['permissions']['deny']")
  assert_eq "only user deny rule remains" "1" "$deny_count"

  # User's hook preserved
  hook_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['hooks']['PreToolUse']")
  assert_eq "user hook preserved after uninstall" "1" "$hook_count"

  existing_cmd=$(json_get "$FAKE_HOME/.claude/settings.json" "data['hooks']['PreToolUse'][0]['hooks'][0]['command']")
  assert_eq "user hook command intact" '"my-custom-hook.sh"' "$existing_cmd"

  # Custom key preserved
  custom=$(json_get "$FAKE_HOME/.claude/settings.json" "data['customKey']")
  assert_eq "custom key preserved after uninstall" '"customValue"' "$custom"

  # Allow key preserved
  allow=$(json_get "$FAKE_HOME/.claude/settings.json" "data['permissions']['allow']")
  assert_eq "allow key preserved after uninstall" '["Read(**/*.md)"]' "$allow"
teardown

echo ""
echo "=== Test 7: Uninstall is idempotent ==="
setup
  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1
  bash "$SCRIPT_DIR/uninstall.sh" > /dev/null 2>&1
  bash "$SCRIPT_DIR/uninstall.sh" > /dev/null 2>&1

  assert_file_exists "settings.json still exists" "$FAKE_HOME/.claude/settings.json"
  assert_file_not_exists "hook still absent" "$FAKE_HOME/.claude/hooks/security-validator.py"
teardown

echo ""
echo "=== Test 8: Uninstall on clean system (nothing installed) ==="
setup
  bash "$SCRIPT_DIR/uninstall.sh" > /dev/null 2>&1
  # Should not fail and not create anything
  assert_file_not_exists "no settings.json created" "$FAKE_HOME/.claude/settings.json"
  assert_file_not_exists "no hook file created" "$FAKE_HOME/.claude/hooks/security-validator.py"
teardown

echo ""
echo "=== Test 9: Full cycle (install -> uninstall -> install) ==="
setup
  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1
  bash "$SCRIPT_DIR/uninstall.sh" > /dev/null 2>&1
  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1

  deny_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['permissions']['deny']")
  assert_eq "deny list has 37 rules after reinstall" "37" "$deny_count"

  hook_count=$(json_len "$FAKE_HOME/.claude/settings.json" "data['hooks']['PreToolUse']")
  assert_eq "PreToolUse has 1 entry after reinstall" "1" "$hook_count"

  assert_file_exists "hook file exists after reinstall" "$FAKE_HOME/.claude/hooks/security-validator.py"
  assert_file_executable "hook file executable after reinstall" "$FAKE_HOME/.claude/hooks/security-validator.py"
teardown

echo ""
echo "=== Test 10: Security validator blocks rm at root/home ==="
setup
  bash "$SCRIPT_DIR/install.sh" > /dev/null 2>&1

  result=$(echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | python3 "$FAKE_HOME/.claude/hooks/security-validator.py" 2>&1 && echo "exit:0" || echo "exit:$?")
  assert_eq "rm -rf / blocked (exit 2)" "exit:2" "$(echo "$result" | grep -o 'exit:[0-9]*')"

  result=$(echo '{"tool_name":"Bash","tool_input":{"command":"rm /*"}}' | python3 "$FAKE_HOME/.claude/hooks/security-validator.py" 2>&1 && echo "exit:0" || echo "exit:$?")
  assert_eq "rm /* blocked (exit 2)" "exit:2" "$(echo "$result" | grep -o 'exit:[0-9]*')"

  result=$(echo '{"tool_name":"Bash","tool_input":{"command":"rm -r ~/"}}' | python3 "$FAKE_HOME/.claude/hooks/security-validator.py" 2>&1 && echo "exit:0" || echo "exit:$?")
  assert_eq "rm -r ~/ blocked (exit 2)" "exit:2" "$(echo "$result" | grep -o 'exit:[0-9]*')"

  result=$(echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf ./build"}}' | python3 "$FAKE_HOME/.claude/hooks/security-validator.py" 2>&1 && echo "exit:0" || echo "exit:$?")
  assert_eq "rm -rf ./build allowed (exit 0)" "exit:0" "$(echo "$result" | grep -o 'exit:[0-9]*')"

  result=$(echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | python3 "$FAKE_HOME/.claude/hooks/security-validator.py" 2>&1 && echo "exit:0" || echo "exit:$?")
  assert_eq "ls -la allowed (exit 0)" "exit:0" "$(echo "$result" | grep -o 'exit:[0-9]*')"

  result=$(echo '{"tool_name":"Read","tool_input":{"file":"/etc/passwd"}}' | python3 "$FAKE_HOME/.claude/hooks/security-validator.py" 2>&1 && echo "exit:0" || echo "exit:$?")
  assert_eq "non-Bash tool allowed (exit 0)" "exit:0" "$(echo "$result" | grep -o 'exit:[0-9]*')"
teardown

# --- Summary ---
echo ""
echo "==============================="
echo "Results: $PASSED passed, $FAILED failed"
echo "==============================="

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
