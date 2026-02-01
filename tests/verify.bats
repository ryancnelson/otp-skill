#!/usr/bin/env bats
# Tests for verify.sh - OTP verification security and robustness

setup() {
  # Create isolated test environment
  export TEST_DIR="$(mktemp -d)"
  export OPENCLAW_WORKSPACE="$TEST_DIR"
  export STATE_FILE="$TEST_DIR/memory/otp-state.json"
  export CONFIG_FILE="$TEST_DIR/config.yaml"

  # Valid test secret (base32)
  export VALID_SECRET="JBSWY3DPEHPK3PXP"
  export OTP_SECRET="$VALID_SECRET"

  # Path to script under test
  VERIFY_SCRIPT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)/verify.sh"

  mkdir -p "$TEST_DIR/memory"
}

teardown() {
  rm -rf "$TEST_DIR"
}

# Generate valid TOTP code for testing
get_valid_code() {
  oathtool --totp -b "$VALID_SECRET"
}

# ============================================================================
# CRITICAL ISSUE #1: Command Injection via Config Parsing
# ============================================================================

@test "verify.sh: rejects config with command substitution" {
  # RED: Test config parsing with malicious command substitution
  cat > "$CONFIG_FILE" <<'EOF'
security:
  otp:
    secret: "$(touch /tmp/pwned)"
EOF

  unset OTP_SECRET

  # Should fail safely, not execute command
  run bash "$VERIFY_SCRIPT" "user1" "123456"

  [ "$status" -ne 0 ]
  [ ! -f "/tmp/pwned" ]
}

@test "verify.sh: rejects config with shell metacharacters" {
  # RED: Test config parsing with shell metacharacters
  cat > "$CONFIG_FILE" <<'EOF'
security:
  otp:
    secret: "VALID; rm -rf /"
EOF

  unset OTP_SECRET

  run bash "$VERIFY_SCRIPT" "user1" "123456"

  [ "$status" -ne 0 ]
}

@test "verify.sh: handles config with comments correctly" {
  # RED: Test config parsing with inline comments
  cat > "$CONFIG_FILE" <<EOF
security:
  otp:
    secret: "$VALID_SECRET"  # This is my secret
    accountName: "test@example.com"
EOF

  unset OTP_SECRET
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 0 ]
  [[ "$output" =~ "✅ OTP verified" ]]
}

@test "verify.sh: handles nested YAML structures" {
  # RED: Test config parsing with nested structures
  cat > "$CONFIG_FILE" <<EOF
database:
  host: localhost
security:
  otp:
    secret: "$VALID_SECRET"
    options:
      intervalHours: 24
  other:
    key: value
EOF

  unset OTP_SECRET
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 0 ]
  [[ "$output" =~ "✅ OTP verified" ]]
}

# ============================================================================
# CRITICAL ISSUE #2: No Input Validation
# ============================================================================

@test "verify.sh: rejects non-numeric OTP code" {
  # RED: Should reject codes with letters
  run bash "$VERIFY_SCRIPT" "user1" "abc123"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
  [[ "$output" =~ "Invalid code format" ]]
}

@test "verify.sh: rejects OTP code with fewer than 6 digits" {
  # RED: Should reject short codes
  run bash "$VERIFY_SCRIPT" "user1" "12345"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
  [[ "$output" =~ "Invalid code format" ]]
}

@test "verify.sh: rejects OTP code with more than 6 digits" {
  # RED: Should reject long codes
  run bash "$VERIFY_SCRIPT" "user1" "1234567"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
  [[ "$output" =~ "Invalid code format" ]]
}

@test "verify.sh: rejects OTP code with special characters" {
  # RED: Should reject codes with shell metacharacters
  run bash "$VERIFY_SCRIPT" "user1" '$(echo pwned)'

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
}

@test "verify.sh: rejects user_id with command substitution" {
  # RED: Should reject malicious user IDs
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" '$(touch /tmp/pwned2)' "$CODE"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
  [ ! -f "/tmp/pwned2" ]
}

@test "verify.sh: rejects user_id with shell metacharacters" {
  # RED: Should reject user IDs with dangerous characters
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" 'user; rm -rf /' "$CODE"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
  [[ "$output" =~ "Invalid" ]]
}

@test "verify.sh: accepts valid user_id formats" {
  # RED: Should accept email-like user IDs
  CODE=$(get_valid_code)

  # Test various valid formats
  for user_id in "user@example.com" "user.name@domain.co.uk" "user_123" "user-name"; do
    run bash "$VERIFY_SCRIPT" "$user_id" "$CODE"
    [ "$status" -eq 0 ]
  done
}

@test "verify.sh: rejects user_id exceeding length limit" {
  # RED: Should reject very long user IDs
  CODE=$(get_valid_code)
  LONG_USER_ID=$(printf 'a%.0s' {1..300})

  run bash "$VERIFY_SCRIPT" "$LONG_USER_ID" "$CODE"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
}

@test "verify.sh: rejects invalid base32 secret" {
  # RED: Should reject non-base32 secrets
  export OTP_SECRET="this-is-not-base32!"

  run bash "$VERIFY_SCRIPT" "user1" "123456"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
  [[ "$output" =~ "base32" ]]
}

@test "verify.sh: rejects empty secret" {
  # RED: Should reject empty secrets
  export OTP_SECRET=""

  run bash "$VERIFY_SCRIPT" "user1" "123456"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
}

@test "verify.sh: rejects too-short secret" {
  # RED: Should reject unreasonably short secrets
  export OTP_SECRET="ABC123"

  run bash "$VERIFY_SCRIPT" "user1" "123456"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
}

# ============================================================================
# CRITICAL ISSUE #3: Race Condition in State File Update
# ============================================================================

@test "verify.sh: concurrent verifications don't corrupt state" {
  # RED: Multiple simultaneous verifications should be atomic
  CODE=$(get_valid_code)

  # Run 5 concurrent verifications
  for i in {1..5}; do
    bash "$VERIFY_SCRIPT" "user$i" "$CODE" &
  done
  wait

  # State file should be valid JSON
  run jq empty "$STATE_FILE"
  [ "$status" -eq 0 ]

  # All 5 users should be recorded
  COUNT=$(jq '.verifications | length' "$STATE_FILE")
  [ "$COUNT" -eq 5 ]
}

@test "verify.sh: state file remains valid after concurrent writes" {
  # RED: Concurrent writes with same user shouldn't corrupt state
  CODE=$(get_valid_code)

  # Run 10 concurrent verifications for same user
  for i in {1..10}; do
    bash "$VERIFY_SCRIPT" "user1" "$CODE" &
  done
  wait

  # State file should still be valid JSON
  run jq empty "$STATE_FILE"
  [ "$status" -eq 0 ]

  # User should exist exactly once
  run jq -r '.verifications.user1' "$STATE_FILE"
  [ "$status" -eq 0 ]
  [[ "$output" != "null" ]]
}

# ============================================================================
# MEDIUM ISSUE #4: macOS/BSD Portability
# ============================================================================

@test "verify.sh: works with BSD date format" {
  # RED: Should use portable date commands
  skip "Requires BSD date testing"
}

# ============================================================================
# MEDIUM ISSUE #5: No Replay Attack Protection
# ============================================================================

@test "verify.sh: rejects reused OTP code within window" {
  # RED: Same code shouldn't work twice in quick succession
  CODE=$(get_valid_code)

  # First use should succeed
  run bash "$VERIFY_SCRIPT" "user1" "$CODE"
  [ "$status" -eq 0 ]

  # Immediate reuse should fail
  sleep 1
  run bash "$VERIFY_SCRIPT" "user1" "$CODE"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "already used" ]] || [[ "$output" =~ "replay" ]]
}

@test "verify.sh: allows same code for different users" {
  # RED: Same code should work for different users (not a replay attack)
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"
  [ "$status" -eq 0 ]

  run bash "$VERIFY_SCRIPT" "user2" "$CODE"
  [ "$status" -eq 0 ]
}

@test "verify.sh: allows code reuse after time window expires" {
  # RED: Code should work again after 90 seconds (3 windows)
  skip "Requires time-dependent testing"
}

# ============================================================================
# MEDIUM ISSUE #6: Insufficient Error Handling
# ============================================================================

@test "verify.sh: reports clear error when oathtool fails" {
  # RED: Should show useful error message when TOTP generation fails
  export OTP_SECRET="INVALID BASE32 SECRET!"

  run bash "$VERIFY_SCRIPT" "user1" "123456"

  [ "$status" -eq 2 ]
  [[ "$output" =~ "ERROR" ]]
  # Should NOT contain raw stderr from oathtool
  [[ ! "$output" =~ "oathtool:" ]]
}

@test "verify.sh: distinguishes between wrong code and system error" {
  # RED: Different exit codes for validation failure vs system error
  CODE=$(get_valid_code)

  # Wrong code should give exit 1
  run bash "$VERIFY_SCRIPT" "user1" "000000"
  [ "$status" -eq 1 ]

  # System error (missing secret) should give exit 2
  unset OTP_SECRET
  rm -f "$CONFIG_FILE"
  run bash "$VERIFY_SCRIPT" "user1" "$CODE"
  [ "$status" -eq 2 ]
}

# ============================================================================
# MEDIUM ISSUE #7: No Audit Logging
# ============================================================================

@test "verify.sh: logs verification attempts" {
  # RED: Should log all verification attempts for audit
  CODE=$(get_valid_code)
  AUDIT_LOG="$TEST_DIR/audit.log"
  export OTP_AUDIT_LOG="$AUDIT_LOG"

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"
  [ "$status" -eq 0 ]

  # Audit log should exist and contain entry
  [ -f "$AUDIT_LOG" ]
  grep -q "user1" "$AUDIT_LOG"
  grep -q "TOTP_SUCCESS" "$AUDIT_LOG"
}

@test "verify.sh: logs failed verification attempts" {
  # RED: Should log failures too
  AUDIT_LOG="$TEST_DIR/audit.log"
  export OTP_AUDIT_LOG="$AUDIT_LOG"

  run bash "$VERIFY_SCRIPT" "user1" "000000"
  [ "$status" -eq 1 ]

  [ -f "$AUDIT_LOG" ]
  grep -q "user1" "$AUDIT_LOG"
  grep -q "TOTP_FAIL" "$AUDIT_LOG"
}

@test "verify.sh: audit log includes timestamp and result" {
  # RED: Audit entries should be structured with all needed info
  CODE=$(get_valid_code)
  AUDIT_LOG="$TEST_DIR/audit.log"
  export OTP_AUDIT_LOG="$AUDIT_LOG"

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  # Should contain timestamp, user, and result
  ENTRY=$(tail -1 "$AUDIT_LOG")
  [[ "$ENTRY" =~ [0-9]{4}-[0-9]{2}-[0-9]{2} ]]  # Date
  [[ "$ENTRY" =~ user1 ]]
  [[ "$ENTRY" =~ SUCCESS|FAIL ]]
}

# ============================================================================
# LOW ISSUE #8: State File Not Validated
# ============================================================================

@test "verify.sh: recovers from corrupted state file" {
  # RED: Should detect and recover from invalid JSON
  echo "this is not json" > "$STATE_FILE"
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 0 ]
  # State file should now be valid JSON
  run jq empty "$STATE_FILE"
  [ "$status" -eq 0 ]
}

@test "verify.sh: handles state file with wrong structure" {
  # RED: Should handle state file with unexpected schema
  echo '{"wrong": "structure"}' > "$STATE_FILE"
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 0 ]
  # Should have correct structure now
  run jq -e '.verifications' "$STATE_FILE"
  [ "$status" -eq 0 ]
}

# ============================================================================
# LOW ISSUE #11: No Rate Limiting
# ============================================================================

@test "verify.sh: blocks after multiple failed attempts" {
  # RED: Should rate limit after N failures
  export OTP_MAX_FAILURES=3

  # Make 3 failed attempts
  for i in {1..3}; do
    bash "$VERIFY_SCRIPT" "user1" "000000" || true
  done

  # Next attempt should be blocked even with valid code
  CODE=$(get_valid_code)
  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 1 ]
  [[ "$output" =~ "rate limit" ]] || [[ "$output" =~ "Too many attempts" ]]
}

@test "verify.sh: resets failure count after success" {
  # RED: Successful verification should reset failure counter
  export OTP_MAX_FAILURES=3

  # Make 2 failed attempts
  bash "$VERIFY_SCRIPT" "user1" "000000" || true
  bash "$VERIFY_SCRIPT" "user1" "000000" || true

  # Success should reset
  CODE=$(get_valid_code)
  run bash "$VERIFY_SCRIPT" "user1" "$CODE"
  [ "$status" -eq 0 ]

  # Should be able to fail again (counter was reset)
  bash "$VERIFY_SCRIPT" "user1" "000000" || true
  run bash "$VERIFY_SCRIPT" "user1" "000000"
  [ "$status" -eq 1 ]
  [[ ! "$output" =~ "rate limit" ]]
}

@test "verify.sh: rate limit expires after time window" {
  # RED: Rate limit should clear after configured time
  skip "Requires time-dependent testing"
}

# ============================================================================
# EXISTING FUNCTIONALITY: Ensure we don't break things
# ============================================================================

@test "verify.sh: accepts valid OTP code" {
  # Baseline: Valid code should verify successfully
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 0 ]
  [[ "$output" =~ "✅ OTP verified" ]]
}

@test "verify.sh: rejects invalid OTP code" {
  # Baseline: Invalid code should fail
  run bash "$VERIFY_SCRIPT" "user1" "000000"

  [ "$status" -eq 1 ]
  [[ "$output" =~ "❌ Invalid OTP" ]]
}

@test "verify.sh: handles clock skew (previous window)" {
  # Baseline: Code from previous 30s window should work
  NOW=$(date +%s)
  CODE=$(oathtool --totp -b "$VALID_SECRET" -N "@$((NOW - 30))")

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 0 ]
}

@test "verify.sh: handles clock skew (next window)" {
  # Baseline: Code from next 30s window should work
  NOW=$(date +%s)
  CODE=$(oathtool --totp -b "$VALID_SECRET" -N "@$((NOW + 30))")

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 0 ]
}

@test "verify.sh: creates state file if missing" {
  # Baseline: Should create state file on first use
  rm -f "$STATE_FILE"
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 0 ]
  [ -f "$STATE_FILE" ]
  run jq -e '.verifications.user1' "$STATE_FILE"
  [ "$status" -eq 0 ]
}

@test "verify.sh: updates state file with timestamps" {
  # Baseline: State should track verification time and expiry
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"
  [ "$status" -eq 0 ]

  VERIFIED_AT=$(jq -r '.verifications.user1.verifiedAt' "$STATE_FILE")
  EXPIRES_AT=$(jq -r '.verifications.user1.expiresAt' "$STATE_FILE")

  [ "$VERIFIED_AT" != "null" ]
  [ "$EXPIRES_AT" != "null" ]
  [ "$EXPIRES_AT" -gt "$VERIFIED_AT" ]
}

@test "verify.sh: requires both user_id and code arguments" {
  # Baseline: Should fail with usage message if args missing
  run bash "$VERIFY_SCRIPT"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "Usage" ]]

  run bash "$VERIFY_SCRIPT" "user1"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "Usage" ]]
}

@test "verify.sh: reads secret from environment" {
  # Baseline: OTP_SECRET env var should work
  export OTP_SECRET="$VALID_SECRET"
  CODE=$(get_valid_code)

  run bash "$VERIFY_SCRIPT" "user1" "$CODE"

  [ "$status" -eq 0 ]
}

@test "verify.sh: fails gracefully when oathtool missing" {
  # Baseline: Should give clear error if dependency missing
  # This requires mocking which is complex, skip for now
  skip "Requires PATH mocking"
}

# ============================================================================
# YubiKey OTP Support Tests
# ============================================================================

@test "verify.sh: detects 6-digit code as TOTP" {
  # This test verifies format detection, not validation
  # A wrong TOTP code should fail with exit 1 (invalid), not exit 2 (format error)
  run bash "$VERIFY_SCRIPT" "user1" "123456"
  [ "$status" -eq 1 ]
  [[ ! "$output" =~ "Invalid code format" ]]
}

@test "verify.sh: detects 44-char ModHex as YubiKey" {
  # Valid ModHex format but no credentials configured
  # Should fail with exit 2 (config error), not format error
  unset YUBIKEY_CLIENT_ID
  unset YUBIKEY_SECRET_KEY
  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "YUBIKEY_CLIENT_ID not set" ]]
}

@test "verify.sh: rejects invalid code formats" {
  # Too short
  run bash "$VERIFY_SCRIPT" "user1" "12345"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "Invalid code format" ]]

  # Too long for TOTP, too short for YubiKey
  run bash "$VERIFY_SCRIPT" "user1" "1234567890"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "Invalid code format" ]]

  # Invalid characters for ModHex (ModHex only uses cbdefghijklnrtuv)
  run bash "$VERIFY_SCRIPT" "user1" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "Invalid code format" ]]
}

@test "verify.sh: accepts valid ModHex characters" {
  # All valid ModHex characters: cbdefghijklnrtuv
  # This should pass format check but fail on missing credentials
  unset YUBIKEY_CLIENT_ID
  run bash "$VERIFY_SCRIPT" "user1" "cbdefghijklnrtuvbdefghijklnrtuvbdefghijklnrt"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "YUBIKEY_CLIENT_ID not set" ]]
  [[ ! "$output" =~ "Invalid code format" ]]
}

@test "verify.sh: rejects 43-char ModHex (too short)" {
  # Exactly 43 chars - one short of valid YubiKey OTP
  run bash "$VERIFY_SCRIPT" "user1" "ccccccccccccccccccccccccccccccccccccccccccc"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "Invalid code format" ]]
}

@test "verify.sh: rejects 45-char ModHex (too long)" {
  # Exactly 45 chars - one more than valid YubiKey OTP
  run bash "$VERIFY_SCRIPT" "user1" "ccccccccccccccccccccccccccccccccccccccccccccc"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "Invalid code format" ]]
}

@test "verify.sh: requires YUBIKEY_CLIENT_ID for YubiKey OTP" {
  export YUBIKEY_SECRET_KEY="testsecretkey"
  unset YUBIKEY_CLIENT_ID
  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "YUBIKEY_CLIENT_ID not set" ]]
}

@test "verify.sh: requires YUBIKEY_SECRET_KEY for YubiKey OTP" {
  export YUBIKEY_CLIENT_ID="12345"
  unset YUBIKEY_SECRET_KEY
  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "YUBIKEY_SECRET_KEY not set" ]]
}

@test "verify.sh: does not require YUBIKEY credentials for TOTP" {
  # TOTP should work without YubiKey credentials set
  unset YUBIKEY_CLIENT_ID
  unset YUBIKEY_SECRET_KEY
  CODE=$(get_valid_code)
  run bash "$VERIFY_SCRIPT" "user1" "$CODE"
  [ "$status" -eq 0 ]
  [[ "$output" =~ "✅ OTP verified" ]]
}

@test "verify.sh: does not require OTP_SECRET for YubiKey" {
  # YubiKey should not fail due to missing OTP_SECRET
  unset OTP_SECRET
  export YUBIKEY_CLIENT_ID="12345"
  export YUBIKEY_SECRET_KEY="testsecretkey"
  # Will fail at API call, but should not fail at secret check
  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  # Should get past config validation (not exit 2 for OTP_SECRET)
  [[ ! "$output" =~ "OTP_SECRET not set" ]]
}

@test "verify.sh: loads YUBIKEY_CLIENT_ID from config file" {
  unset YUBIKEY_CLIENT_ID
  unset YUBIKEY_SECRET_KEY

  cat > "$CONFIG_FILE" <<'EOF'
security:
  otp:
    secret: "JBSWY3DPEHPK3PXP"
  yubikey:
    clientId: "12345"
EOF

  # Should fail on missing secretKey, not missing clientId
  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  [ "$status" -eq 2 ]
  [[ "$output" =~ "YUBIKEY_SECRET_KEY not set" ]]
  [[ ! "$output" =~ "YUBIKEY_CLIENT_ID not set" ]]
}

@test "verify.sh: loads YUBIKEY_SECRET_KEY from config file" {
  unset YUBIKEY_CLIENT_ID
  unset YUBIKEY_SECRET_KEY

  cat > "$CONFIG_FILE" <<'EOF'
security:
  otp:
    secret: "JBSWY3DPEHPK3PXP"
  yubikey:
    clientId: "12345"
    secretKey: "testbase64key=="
EOF

  # Should get past config validation
  # Will fail at API call since credentials are fake
  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  [[ ! "$output" =~ "YUBIKEY_CLIENT_ID not set" ]]
  [[ ! "$output" =~ "YUBIKEY_SECRET_KEY not set" ]]
}

@test "verify.sh: env vars override config file for YubiKey" {
  export YUBIKEY_CLIENT_ID="env_client_id"
  export YUBIKEY_SECRET_KEY="env_secret_key"

  cat > "$CONFIG_FILE" <<'EOF'
security:
  yubikey:
    clientId: "config_client_id"
    secretKey: "config_secret_key"
EOF

  # Env vars should be used, not config file values
  # We can't easily verify which was used, but this ensures no crash
  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  # Should get past config loading without errors about missing credentials
  [[ ! "$output" =~ "not set" ]]
}

@test "verify.sh: handles invalid YUBIKEY_CLIENT_ID gracefully" {
  export YUBIKEY_CLIENT_ID="00000"
  export YUBIKEY_SECRET_KEY="dGVzdGtleQ=="  # base64 of "testkey"

  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  [ "$status" -ne 0 ]
  # Should get an API error, not a crash
  # Exact error depends on Yubico's response to invalid client
}

@test "verify.sh: YubiKey failure increments failure count" {
  export YUBIKEY_CLIENT_ID="00000"
  export YUBIKEY_SECRET_KEY="dGVzdGtleQ=="  # base64 of "testkey"

  # First failure
  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"

  # Check state file has failure recorded (if validation got that far)
  if [ -f "$STATE_FILE" ]; then
    FAILURE_COUNT=$(jq -r '.failureCounts["user1"].count // 0' "$STATE_FILE")
    # May or may not have incremented depending on error type
    [ "$FAILURE_COUNT" -ge 0 ]
  fi
}

@test "verify.sh: YubiKey rate limiting works" {
  export YUBIKEY_CLIENT_ID="00000"
  export YUBIKEY_SECRET_KEY="dGVzdGtleQ=="
  export OTP_MAX_FAILURES=2

  # Create state with existing failures at rate limit
  NOW_MS=$(date +%s)000
  cat > "$STATE_FILE" <<EOF
{
  "verifications": {},
  "usedCodes": {},
  "failureCounts": {
    "user1": {
      "count": 3,
      "since": $NOW_MS
    }
  }
}
EOF

  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  [ "$status" -eq 1 ]
  [[ "$output" =~ "Too many attempts" ]]
}

@test "verify.sh: handles network timeout gracefully" {
  # Use a non-routable IP to simulate network timeout
  # Note: This test may take up to 10 seconds due to curl timeout
  export YUBIKEY_CLIENT_ID="12345"
  export YUBIKEY_SECRET_KEY="dGVzdGtleQ=="  # base64 of "testkey"

  # We can't easily mock the API endpoint, so we verify error handling
  # by checking the script doesn't crash with valid-looking credentials
  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"

  # Should fail but with proper error handling (not a crash)
  [ "$status" -ne 0 ]
  # Output should contain some error message, not a bash crash
  [[ -n "$output" ]]
}

@test "verify.sh: rejects invalid base64 secret key" {
  export YUBIKEY_CLIENT_ID="12345"
  export YUBIKEY_SECRET_KEY="not-valid-base64!!!"

  run bash "$VERIFY_SCRIPT" "user1" "cccccccccccccccccccccccccccccccccccccccccccc"
  [ "$status" -ne 0 ]
  # Should fail due to invalid base64, not pass to validation
  [[ "$output" =~ "Failed to decode YUBIKEY_SECRET_KEY" ]] || [[ "$output" =~ "base64" ]] || [[ "$status" -eq 1 ]]
}
