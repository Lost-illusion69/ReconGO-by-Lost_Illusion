#!/usr/bin/env bash
# setup-commit-signing.sh — configure and verify SSH commit signing for GitHub.
#
# GitHub shows commits as:
#   Verified   — SSH/GPG signature matches a signing key on your account
#   Unverified — signed, but the key is NOT registered on your account
#   (no badge) — unsigned commit
#   Merge PRs  — always Verified (signed by GitHub when merged via the UI)
#
# Cloud Agent commits are SSH-signed automatically; register the public key once
# on https://github.com/settings/ssh/new (Key type: Signing Key).

set -euo pipefail

GITHUB_USER="${GITHUB_USER:-Lost-illusion69}"
NOREPLY_EMAIL="72228286+Lost-illusion69@users.noreply.github.com"

echo "=== ReconGo Git Commit Signing Setup ==="
echo

# Identity (attribution)
git config --global user.name "Lost_illusion"
git config --global user.email "$NOREPLY_EMAIL"
echo "✓ Git identity: Lost_illusion <$NOREPLY_EMAIL>"

# SSH signing (Git 2.34+)
git config --global gpg.format ssh
git config --global commit.gpgsign true
echo "✓ commit.gpgsign=true, gpg.format=ssh"

# Resolve signing key
SIGNING_KEY=""
if [[ -n "${GIT_SIGNING_KEY:-}" ]]; then
	SIGNING_KEY="$GIT_SIGNING_KEY"
elif key=$(git config --global user.signingkey 2>/dev/null); then
	SIGNING_KEY="$key"
fi

if [[ -z "$SIGNING_KEY" ]]; then
	KEY_PATH="${HOME}/.ssh/recongo_signing_ed25519"
	if [[ ! -f "$KEY_PATH" ]]; then
		echo "→ Generating new Ed25519 signing key at $KEY_PATH"
		ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" -C "${GITHUB_USER}@recongo-signing"
	fi
	SIGNING_KEY="${KEY_PATH}.pub"
	git config --global user.signingkey "$SIGNING_KEY"
fi

echo "✓ Signing key: $SIGNING_KEY"
echo
echo "Public key (add this to GitHub as a SIGNING key):"
echo "────────────────────────────────────────────────"
if [[ -f "$SIGNING_KEY" ]]; then
	cat "$SIGNING_KEY"
elif [[ "$SIGNING_KEY" == ssh-* ]]; then
	echo "$SIGNING_KEY"
else
	echo "(could not read key file)"
fi
echo "────────────────────────────────────────────────"
echo
echo "One-time GitHub setup:"
echo "  1. Open https://github.com/settings/ssh/new"
echo "  2. Title: Cursor Cloud Agent (ReconGo signing)"
echo "  3. Key type: Signing Key  ← important (not Authentication)"
echo "  4. Paste the public key above → Add SSH key"
echo
echo "Or via gh CLI (must be logged in as ${GITHUB_USER}):"
echo "  gh auth login"
echo "  gh ssh-key add -t 'ReconGo signing' --type signing <(git config user.signingkey | sed 's/^file://;s|^|'"$HOME"'/|')"
echo

# Quick local verification
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
git -C "$TMP" init -q
git -C "$TMP" config user.name "Lost_illusion"
git -C "$TMP" config user.email "$NOREPLY_EMAIL"
git -C "$TMP" config gpg.format ssh
git -C "$TMP" config user.signingkey "$SIGNING_KEY"
git -C "$TMP" config commit.gpgsign true
git -C "$TMP" commit --allow-empty -m "signing smoke test" -q 2>/dev/null || true
if git -C "$TMP" log -1 --format='%G?' 2>/dev/null | grep -qE 'G|U'; then
	echo "✓ Local signature created (G=good, U=unknown key on GitHub until registered)"
else
	echo "⚠ Local signing check inconclusive — ensure OpenSSH ssh-keygen is available"
fi
echo
echo "After registering the key, new commits will show Verified on GitHub."
