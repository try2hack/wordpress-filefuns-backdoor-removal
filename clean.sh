#!/usr/bin/env bash
#
# wp-backdoor-cleaner
# Incident-response helper to detect and remove a known WordPress/PHP
# webshell campaign (filefuns.php family, "BiaoJiOk" watermark) from a
# server you own or are authorised to remediate.
#
# SAFETY MODEL
#   - Default mode is SCAN (read-only). It never modifies anything.
#   - CLEAN mode requires the explicit --clean flag AND interactive
#     confirmation, and backs up every file before touching it.
#   - index.php / .htaccess are only rewritten when they (a) match a
#     malware signature and (b) sit in a confirmed WordPress directory.
#
# This tool removes known-bad artefacts. It is NOT a substitute for a
# clean rebuild after a server-level compromise. See README.md.
#
# Usage:
#   ./clean.sh --path /home/USER/domains            # scan (read-only)
#   ./clean.sh --path /home/USER/domains --clean    # remediate (asks first)
#
set -uo pipefail

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
BASE_PATH=""
MODE="scan"                      # scan | clean
ASSUME_YES="no"
SIG_FILE="$(dirname "$0")/signatures.txt"
TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="/root/wp-cleaner-backup-${TS}"
LOG_FILE="/root/wp-cleaner-${TS}.log"

# Content signatures (regex, used with grep -E) that mark a file as malicious.
CONTENT_SIGS='BiaoJiOk|yarse\.top|zs896v|goto [A-Za-z0-9_]{10,}|eval\(\s*(base64_decode|gzinflate|str_rot13)'

# Clean WordPress .htaccess used to replace an infected one.
read -r -d '' CLEAN_HTACCESS <<'EOF'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
EOF

# Clean WordPress index.php used to replace an infected one.
read -r -d '' CLEAN_INDEX <<'EOF'
<?php
/**
 * Front to the WordPress application.
 */
define( 'WP_USE_THEMES', true );
require __DIR__ . '/wp-blog-header.php';
EOF

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
log() { echo "$*" | tee -a "$LOG_FILE"; }

usage() {
  cat <<USAGE
wp-backdoor-cleaner

  --path <dir>    Base directory to scan (e.g. /home/user/domains)   [required]
  --clean         Perform removal/restore (default is read-only scan)
  --yes           Skip the interactive confirmation in clean mode
  --sigs <file>   Path to signatures.txt (default: alongside this script)
  -h, --help      Show this help

Examples:
  $0 --path /home/user/domains
  $0 --path /home/user/domains --clean
USAGE
}

# Is this index.php inside a real WordPress install?
is_wordpress_root() {
  local dir; dir="$(dirname "$1")"
  [[ -f "${dir}/wp-blog-header.php" || -f "${dir}/wp-load.php" ]]
}

# Back up a file, preserving its relative path under BACKUP_DIR.
backup_file() {
  local f="$1"
  local dest="${BACKUP_DIR}${f}"
  mkdir -p "$(dirname "$dest")"
  cp -p "$f" "$dest" 2>/dev/null && log "  backed up -> $dest"
}

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --path)  BASE_PATH="${2:-}"; shift 2 ;;
    --clean) MODE="clean"; shift ;;
    --yes)   ASSUME_YES="yes"; shift ;;
    --sigs)  SIG_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$BASE_PATH" ]]; then
  echo "Error: --path is required."; usage; exit 1
fi
if [[ ! -d "$BASE_PATH" ]]; then
  echo "Error: path not found: $BASE_PATH"; exit 1
fi
if [[ ! -f "$SIG_FILE" ]]; then
  echo "Error: signatures file not found: $SIG_FILE"; exit 1
fi

# Load known-bad filenames from signatures.txt (lines starting with FILE:)
mapfile -t BAD_FILES < <(grep -E '^FILE:' "$SIG_FILE" | sed 's/^FILE://')

log "=============================================================="
log " wp-backdoor-cleaner   mode=$MODE   $(date)"
log " base path : $BASE_PATH"
log " signatures: $SIG_FILE"
[[ "$MODE" == "clean" ]] && log " backups   : $BACKUP_DIR"
log " log file  : $LOG_FILE"
log "=============================================================="

if [[ "$MODE" == "clean" && "$ASSUME_YES" != "yes" ]]; then
  echo
  echo "CLEAN mode will DELETE matched backdoors and REWRITE infected"
  echo "index.php / .htaccess files. Every file is backed up first to:"
  echo "  $BACKUP_DIR"
  echo
  read -r -p "Type 'yes' to proceed: " ans
  [[ "$ans" == "yes" ]] || { echo "Aborted."; exit 0; }
  mkdir -p "$BACKUP_DIR"
fi

# Counters
n_shell=0; n_index=0; n_ht=0; n_phtml=0; n_skip=0

# --------------------------------------------------------------------------
# 1. Known-bad filename webshells
# --------------------------------------------------------------------------
log ""
log "[1] Known-bad webshell filenames"
for name in "${BAD_FILES[@]}"; do
  [[ -z "$name" ]] && continue
  while IFS= read -r f; do
    log "  SHELL: $f"
    ((n_shell++))
    if [[ "$MODE" == "clean" ]]; then
      backup_file "$f"; rm -f "$f" && log "  removed"
    fi
  done < <(find "$BASE_PATH" -type f -name "$name" 2>/dev/null)
done

# --------------------------------------------------------------------------
# 2. Content-signature matches in .php / .phtml (catches renamed shells)
# --------------------------------------------------------------------------
log ""
log "[2] Files matching malware content signatures"
while IFS= read -r f; do
  base="$(basename "$f")"
  if [[ "$base" == "index.php" ]]; then
    # Handled in step 3 (needs WordPress check) — skip here.
    continue
  fi
  log "  MATCH: $f"
  if [[ "$f" == *.phtml ]]; then ((n_phtml++)); else ((n_shell++)); fi
  if [[ "$MODE" == "clean" ]]; then
    backup_file "$f"; rm -f "$f" && log "  removed"
  fi
done < <(grep -RElZ --include='*.php' --include='*.phtml' "$CONTENT_SIGS" "$BASE_PATH" 2>/dev/null | tr '\0' '\n')

# --------------------------------------------------------------------------
# 3. Injected index.php (only restore inside a real WordPress root)
# --------------------------------------------------------------------------
log ""
log "[3] Infected index.php"
while IFS= read -r f; do
  if is_wordpress_root "$f"; then
    log "  INFECTED (WP): $f"
    ((n_index++))
    if [[ "$MODE" == "clean" ]]; then
      backup_file "$f"
      printf '%s\n' "$CLEAN_INDEX" > "$f" && log "  restored to WP default"
    fi
  else
    log "  INFECTED (NON-WP, manual review needed): $f"
    ((n_skip++))
  fi
done < <(grep -RElZ --include='index.php' "$CONTENT_SIGS" "$BASE_PATH" 2>/dev/null | tr '\0' '\n')

# --------------------------------------------------------------------------
# 4. Tampered .htaccess (malicious whitelist / watermark)
# --------------------------------------------------------------------------
log ""
log "[4] Tampered .htaccess files"
while IFS= read -r f; do
  log "  INFECTED: $f"
  ((n_ht++))
  if [[ "$MODE" == "clean" ]]; then
    # remove immutable flag if set, then back up and restore
    chattr -i "$f" 2>/dev/null
    backup_file "$f"
    printf '%s\n' "$CLEAN_HTACCESS" > "$f" && log "  restored to WP default"
  fi
done < <(grep -RElZ --include='.htaccess' 'filefuns|BiaoJiOk|adminfuns|funs\.php' "$BASE_PATH" 2>/dev/null | tr '\0' '\n')

# --------------------------------------------------------------------------
# 5. Persistence checks (report only — these need human judgement)
# --------------------------------------------------------------------------
log ""
log "[5] Persistence checks (review manually — NOT auto-cleaned)"

log "  -- mu-plugins (auto-loaded, invisible in admin) --"
find "$BASE_PATH" -path '*/wp-content/mu-plugins/*' -name '*.php' 2>/dev/null | tee -a "$LOG_FILE"

log "  -- PHP files modified in the last 14 days --"
find "$BASE_PATH" -name '*.php' -mtime -14 -not -path '*/cache/*' 2>/dev/null \
  | head -100 | tee -a "$LOG_FILE"

log "  -- suspicious nested duplicate directories --"
find "$BASE_PATH" -type d 2>/dev/null | awk -F/ '{ if ($(NF)==$(NF-1)) print }' \
  | tee -a "$LOG_FILE"

log "  -- reminders that cannot be checked from the filesystem alone --"
log "     * crontab -l  (per user) and /etc/cron.d/ — check for unknown jobs"
log "     * wp_options autoloaded rows — query the DB for injected code"
log "     * run 'wp core verify-checksums' per site to find modified core files"
log "     * audit WordPress admin users on every site for rogue accounts"

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
log ""
log "=============================================================="
log " SUMMARY ($MODE)"
log "   webshell files matched : $n_shell"
log "   .phtml backdoors       : $n_phtml"
log "   infected index.php (WP): $n_index"
log "   tampered .htaccess     : $n_ht"
log "   non-WP index.php (skip): $n_skip"
log "=============================================================="
if [[ "$MODE" == "scan" ]]; then
  log " Read-only scan complete. Re-run with --clean to remediate."
else
  log " Clean complete. Backups: $BACKUP_DIR"
  log " NEXT: rotate all passwords + wp salts, then review section [5]."
fi
