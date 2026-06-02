# Hardening Guide

Steps to prevent re-infection after cleaning the `filefuns.php` / `BiaoJiOk`
WordPress backdoor campaign. Ordered roughly by impact. Apply on a server you
own or are authorised to administer.

> Context: in the incident this repo was built from, one freshly-created,
> weakly-secured WordPress site was breached and the attacker then wrote
> backdoors into **every** domain under the same shared system user. The two
> biggest lessons — strong credentials on day one, and isolating sites from
> each other — are reflected below.

---

## 1. Credentials (do these first)

After any compromise, assume every secret is known to the attacker.

- **Reset all WordPress admin passwords** — 16+ chars, unique per site.
- **Rotate database passwords** and update each `wp-config.php`.
- **Rotate the hosting panel, SSH, and hosting email passwords.**
- **Invalidate stolen login cookies** by changing the salts in every
  `wp-config.php`. Generate fresh values from
  `https://api.wordpress.org/secret-key/1.1/salt/` and replace the
  `AUTH_KEY` … `NONCE_SALT` block. This forces every existing session to
  re-authenticate.

---

## 2. WordPress hardening (per site)

### Disable in-dashboard file editing
Stops a compromised admin login from editing theme/plugin PHP directly.
In `wp-config.php`:
```php
define( 'DISALLOW_FILE_EDIT', true );
define( 'DISALLOW_FILE_MODS', true ); // also blocks plugin/theme installs+updates from UI
```
> Note: `DISALLOW_FILE_MODS` blocks UI updates too. If you rely on the
> dashboard for updates, set it only on sites you update via WP-CLI/SSH.

### Keep everything patched
The entry point here was an outdated plugin. Update core, themes, and plugins
promptly. With WP-CLI:
```bash
wp core update
wp plugin update --all
wp theme update --all
```
Remove plugins/themes you don't use — inactive code is still attackable.

### Limit login exposure
- Restrict `wp-login.php` to known IPs if you have static addressing, or put it
  behind HTTP auth / a login-limiter plugin (e.g. Limit Login Attempts Reloaded,
  Wordfence).
- Disable XML-RPC if unused. In the site `.htaccess`:
  ```apache
  <Files xmlrpc.php>
    Require all denied
  </Files>
  ```

### Block PHP execution in upload/writable dirs
A webshell dropped into `uploads/` can't run if PHP is disabled there.
Create `wp-content/uploads/.htaccess`:
```apache
<FilesMatch "\.(php|php\d|phtml|phps)$">
  Require all denied
</FilesMatch>
```

---

## 3. Server / PHP hardening

### Restrict dangerous PHP functions
In the PHP-FPM `php.ini` used by your sites:
```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,proc_close,show_source,dl
allow_url_fopen = Off
allow_url_include = Off
```
> Test after applying — some legitimate plugins use `exec`/`proc_open`. Verify
> the live FPM value with `php-fpm -i | grep disable_functions` (the CLI `php`
> binary often uses a different ini).

### Sensible file permissions
```bash
find /home/USER/domains -type d -exec chmod 755 {} \;
find /home/USER/domains -type f -exec chmod 644 {} \;
# wp-config.php tighter:
find /home/USER/domains -name wp-config.php -exec chmod 600 {} \;
```
Web files should **not** be owned by the web-server user where avoidable;
attacker-writable directories are how shells get planted.

### Brute-force protection (Fail2ban)
Ban repeated failed WordPress and SSH logins:
```ini
# /etc/fail2ban/filter.d/wordpress.conf
[Definition]
failregex = <HOST>.*POST.*(wp-login\.php|xmlrpc\.php)
ignoreregex =
```
```ini
# /etc/fail2ban/jail.d/wordpress.conf
[wordpress]
enabled  = true
filter   = wordpress
logpath  = /var/log/httpd/domains/*.log
maxretry = 5
findtime = 300
bantime  = 86400
```
```bash
systemctl enable --now fail2ban
fail2ban-client status wordpress
```
> Don't permanently block residential/dynamic ISP IPs by hand — they recycle to
> innocent users. Let Fail2ban expire bans automatically.

### SSH
```ini
# /etc/ssh/sshd_config
PasswordAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
```
Use key-based auth, and review `~/.ssh/authorized_keys` for unknown keys.

---

## 4. Isolation (the structural fix)

The single most important change for a multi-site server: **one compromised
site must not be able to reach the others.**

- **One system user per domain** (or per customer). On a shared user, every site
  can read and write every other site's files — which is exactly how 17 domains
  were hit from one entry point. In DirectAdmin, host unrelated domains under
  separate user accounts rather than as "additional domains" of one user.
- **`open_basedir` per vhost** so each site's PHP can only access its own tree.
- Keep backups **off the web root** and ideally off the server, so an attacker
  with web access can't tamper with them.

---

## 5. Monitoring & detection

- **File integrity:** `wp core verify-checksums` per site (cron it). Flags any
  modified WordPress core file.
- **Re-scan on a schedule** with this repo's `clean.sh --path ...` (scan mode).
- **Watch for new admin users** and unexpected scheduled tasks
  (`wp cron event list`, `crontab -l`, `/etc/cron.d/`).
- **Check outbound connections** periodically (`ss -tunp`) for C2 traffic.
- Register sites in **Google Search Console** to get notified if Google flags
  the site, and to request review after cleanup.

---

## 6. New-site checklist (prevent the original mistake)

Do this **before** a new WordPress site is reachable — not after:

- [ ] Strong, unique admin password (16+ chars) set at install
- [ ] Core + all plugins/themes updated to latest
- [ ] Unused plugins/themes removed
- [ ] `DISALLOW_FILE_EDIT` set in `wp-config.php`
- [ ] PHP execution blocked in `uploads/`
- [ ] Login limiter / Fail2ban active
- [ ] Site runs under its own isolated system user
- [ ] If not ready to configure it yet, leave a static placeholder page and
      **don't install WordPress until you are** — empty HTML has no attack surface

---

*Defensive guidance only. Apply on systems you own or are authorised to manage.*
