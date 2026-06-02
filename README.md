# wp-backdoor-cleaner

An incident-response helper for detecting and removing a known WordPress/PHP
webshell campaign (the `filefuns.php` family, identifiable by the `BiaoJiOk`
code watermark and the `yarse.top` C2 domain) from servers **you own or are
explicitly authorised to remediate**.

It was written after cleaning a DirectAdmin VPS where a single weakly-secured
WordPress site was compromised and the attacker then spread backdoors across
every domain under the same shared hosting account.

> ⚠️ **This is a remediation aid, not a guarantee of cleanliness.**
> After a server-level compromise, the only fully reliable recovery is to
> rebuild from a known-good backup (or reinstall) and restore only verified
> content. Use this tool to triage and to assist that process — not as a
> substitute for it.

---

## What it does

**Scan mode (default, read-only):**
- Finds webshells by known filename (from `signatures.txt`)
- Finds renamed/unknown shells by content signature (watermark, `goto`
  obfuscation, `eval(base64_decode(...))`, C2 strings)
- Flags injected `index.php` and tampered `.htaccess` files
- Reports likely persistence locations (mu-plugins, recently-modified PHP,
  nested duplicate directories)
- Writes a full log; **changes nothing**

**Clean mode (`--clean`, opt-in):**
- Backs up **every** file to a timestamped directory before any change
- Deletes matched webshells and `.phtml` backdoors
- Restores infected `index.php` **only inside a confirmed WordPress root**
  (a sibling `wp-blog-header.php`/`wp-load.php` must exist), otherwise it just
  flags the file for manual review
- Restores tampered `.htaccess` to the stock WordPress ruleset
- Never auto-touches persistence items in section 5 — those require human
  judgement

---

## Safety design

| Risk | Mitigation |
|------|------------|
| Accidental data loss | Read-only by default; clean mode needs `--clean` **and** typed confirmation |
| Destroying good files | Every modified/deleted file is backed up first |
| Breaking non-WordPress sites | `index.php` is only rewritten in a verified WP root |
| False positives | Detection is primarily content-based; signatures are editable |
| Wiping legitimate config | `.htaccess` restore is logged and backed up; review before trusting |

---

## Requirements

- Linux, `bash` 4+
- `grep`, `find` (GNU coreutils)
- Root or an account that can read/write the target paths
- Optional: `chattr` (to clear immutable flags on locked `.htaccess`)

---

## Usage

```bash
git clone https://github.com/<you>/wp-backdoor-cleaner.git
cd wp-backdoor-cleaner
chmod +x clean.sh

# 1) Always scan first (no changes are made):
./clean.sh --path /home/USER/domains

# 2) Review the log, then clean (you will be asked to confirm):
./clean.sh --path /home/USER/domains --clean
```

Options:

```
--path <dir>    Base directory to scan                 [required]
--clean         Perform removal/restore (default: scan only)
--yes           Skip the confirmation prompt in clean mode
--sigs <file>   Custom signatures file
-h, --help      Help
```

Logs go to `/root/wp-cleaner-<timestamp>.log`; backups to
`/root/wp-cleaner-backup-<timestamp>/`.

---

## After cleaning — do not skip this

Removing files does **not** end the incident. Complete these steps:

1. **Rotate every credential:** WordPress admins (all sites), database users,
   hosting panel, SSH, hosting email accounts.
2. **Invalidate sessions:** change the `AUTH_KEY`/`SALT` values in each
   `wp-config.php` so stolen login cookies stop working.
3. **Hunt remaining persistence (section 5 of the scan output):**
   - `crontab -l` per user and `/etc/cron.d/`
   - `wp-content/mu-plugins/`
   - injected autoloaded rows in the `wp_options` table
   - `wp core verify-checksums` on each site to detect modified core files
   - rogue administrator accounts on every site
4. **Patch the entry point:** update WordPress core, themes, and all plugins
   (this campaign exploited outdated plugin versions on a freshly created site).
5. **Harden:** strong unique admin passwords, restrict `wp-login.php`,
   `define('DISALLOW_FILE_EDIT', true);`, a login-rate limiter (e.g. Fail2ban),
   and — ideally — isolate each domain under its own system user so one
   compromised site cannot reach the others.

---

## Indicators of compromise (IOCs)

| Type | Value |
|------|-------|
| Watermark | `BiaoJiOk` |
| C2 / redirect domain | `yarse.top` (random subdomains) |
| Primary webshell | `filefuns.php` (+ family in `signatures.txt`) |
| Backup backdoor | `*.phtml` in deep folders (`model/`, `structure/`, `property/`) |
| Obfuscation | `goto` + 10+ char random labels; dynamic `eval` |
| Persistence | malicious `.htaccess` whitelist of the shell filenames |

---

## Disclaimer

Provided as-is, for use on systems you own or are authorised to administer.
Always run the scan and review backups before using clean mode. The authors
accept no liability for data loss or misuse. Using it against systems without
authorisation is illegal.

## License

MIT
