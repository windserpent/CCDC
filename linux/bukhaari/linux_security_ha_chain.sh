# CCDC Webmail Server - Fedora 42 Security Kill Chain

## INITIAL RECONNAISSANCE (First 5 Minutes)

### Identify yourself and document baseline
```
whoami
hostname
ip addr show
date
uptime
w
```

### Immediate service check - what's exposed?
```
ss -tulpn
systemctl list-units --type=service --state=running | grep -E 'http|mail|post|dovecot|imap|smtp'
```

### Check for backdoors in common webmail ports
```
lsof -i :80 -i :443 -i :25 -i :587 -i :465 -i :143 -i :993 -i :110 -i :995
```

## PHASE 1: WEBMAIL SERVICE IDENTIFICATION

### Apache/Nginx web server
```
systemctl status httpd nginx
ps aux | grep -E 'httpd|nginx'
```

### Mail transfer agent (Postfix/Sendmail)
```
systemctl status postfix sendmail
postconf -n
```

### IMAP/POP3 server (Dovecot/Courier)
```
systemctl status dovecot courier-imap
doveconf -n
```

### Webmail applications (Roundcube/SquirrelMail/Horde)
```
find /var/www /usr/share -name "*roundcube*" -o -name "*squirrelmail*" -o -name "*horde*" 2>/dev/null
ls -la /var/www/html/
```

### PHP-FPM (webmail dependency)
```
systemctl status php-fpm
ps aux | grep php-fpm
```

## PHASE 2: ACTIVE CONNECTIONS & COMPROMISE CHECK

### Active mail connections (watch for red team)
```
ss -tnp | grep -E ':25|:587|:465|:143|:993'
netstat -anp | grep ESTABLISHED | grep -E ':80|:443'
```

### Check for suspicious processes
```
ps auxf | grep -v grep | grep -E 'nc|ncat|/tmp|/dev/shm'
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null
```

### Recent logins and current users
```
last -20
lastlog
who
w
```

### Check auth logs for brute force
```
journalctl -u sshd -u httpd -u postfix --since "1 hour ago" | grep -i fail
tail -100 /var/log/secure | grep -E 'Failed|Invalid'
```

## PHASE 3: IMMEDIATE LOCKDOWN

### Change ALL passwords NOW
```
passwd
passwd <webmail_user>
```

### Lock unused accounts
```
cat /etc/passwd | grep -v nologin | grep -v false | awk -F: '{print $1}'
usermod -L <suspicious_user>
```

### Kill suspicious connections
```
ss -tnp | grep ESTABLISHED
# Note PIDs, then: kill -9 <PID>
```

### Block red team IPs (if identified)
```
firewall-cmd --add-rich-rule='rule family="ipv4" source address="<RED_TEAM_IP>" reject'
firewall-cmd --runtime-to-permanent
```

## PHASE 4: WEBMAIL APPLICATION SECURITY

### Check webmail config files for backdoors
```
find /var/www /usr/share -name "*.php" -mtime -1 2>/dev/null
grep -r "eval\|base64_decode\|system\|shell_exec" /var/www/html/ 2>/dev/null | head -20
```

### Verify webmail file permissions
```
ls -la /var/www/html/
find /var/www/html -type f -perm -002 2>/dev/null
```

### Check for webshells
```
find /var/www -name "*.php" -type f -exec grep -l "c99\|r57\|b374k\|shell" {} \; 2>/dev/null
```

### Verify web root ownership
```
ls -ld /var/www/html
chown -R apache:apache /var/www/html
chmod -R 755 /var/www/html
find /var/www/html -type f -exec chmod 644 {} \;
```

## PHASE 5: APACHE/NGINX HARDENING

### Check Apache/Nginx config
```
httpd -t
nginx -t
cat /etc/httpd/conf/httpd.conf | grep -v '^#' | grep -v '^$'
cat /etc/nginx/nginx.conf | grep -v '^#' | grep -v '^$'
```

### Disable dangerous modules
```
grep LoadModule /etc/httpd/conf.modules.d/*.conf | grep -E 'userdir|autoindex|status'
```

### Check for malicious vhosts
```
cat /etc/httpd/conf.d/*.conf
ls -la /etc/httpd/conf.d/
```

### SSL/TLS certificate verification
```
ls -la /etc/pki/tls/certs/ /etc/pki/tls/private/
openssl s_client -connect localhost:443 -servername $(hostname)
```

### Restart web server (after config changes)
```
systemctl restart httpd
systemctl restart nginx
```

## PHASE 6: MAIL SERVER (POSTFIX) SECURITY

### Check Postfix config for relaying
```
postconf | grep relay
postconf | grep mynetworks
```

### Lock down relay access
```
postconf -e 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
postconf -e 'mynetworks = 127.0.0.0/8'
```

### Check mail queue for spam
```
mailq
postqueue -p
```

### Flush suspicious mail
```
postsuper -d ALL deferred
postsuper -d ALL
```

### Check Postfix access controls
```
cat /etc/postfix/main.cf | grep -E 'smtpd_recipient_restrictions|smtpd_relay_restrictions'
```

### Verify SMTP auth
```
postconf | grep sasl
systemctl status saslauthd
```

### Restart Postfix
```
systemctl restart postfix
```

## PHASE 7: DOVECOT (IMAP/POP3) HARDENING

### Check Dovecot config
```
doveconf -n | grep -E 'protocols|ssl|auth'
```

### Verify SSL is enforced
```
grep -E 'ssl|disable_plaintext_auth' /etc/dovecot/dovecot.conf /etc/dovecot/conf.d/*.conf
```

### Check auth mechanisms
```
doveconf auth_mechanisms
cat /etc/dovecot/conf.d/10-auth.conf | grep -v '^#'
```

### Monitor mailbox access
```
doveadm who
doveadm log errors
```

### Restart Dovecot
```
systemctl restart dovecot
```

## PHASE 8: FIREWALL CONFIGURATION

### Check current firewall rules
```
firewall-cmd --list-all
iptables -L -n -v
```

### Lock down to required ports only
```
firewall-cmd --zone=public --add-service=http --permanent
firewall-cmd --zone=public --add-service=https --permanent
firewall-cmd --zone=public --add-service=smtp --permanent
firewall-cmd --zone=public --add-service=smtps --permanent
firewall-cmd --zone=public --add-service=submission --permanent
firewall-cmd --zone=public --add-service=imap --permanent
firewall-cmd --zone=public --add-service=imaps --permanent
firewall-cmd --zone=public --add-service=pop3 --permanent
firewall-cmd --zone=public --add-service=pop3s --permanent
firewall-cmd --reload
```

### Remove ALL other ports
```
firewall-cmd --zone=public --list-services
firewall-cmd --zone=public --remove-service=<service> --permanent
```

### Rate limit SSH (if allowed)
```
firewall-cmd --permanent --add-rich-rule='rule service name=ssh limit value=3/m accept'
firewall-cmd --reload
```

## PHASE 9: DATABASE SECURITY (MySQL/MariaDB/PostgreSQL)

### Identify database for webmail
```
systemctl status mariadb mysql postgresql
ps aux | grep -E 'mysql|postgres'
```

### Check database users
```
mysql -e "SELECT user,host FROM mysql.user;"
```

### Secure root and remove test databases
```
mysql -e "DELETE FROM mysql.user WHERE User='';"
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -e "DROP DATABASE IF EXISTS test;"
mysql -e "FLUSH PRIVILEGES;"
```

### Change database passwords
```
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewStrongPassword123!';"
mysql -e "ALTER USER 'roundcube'@'localhost' IDENTIFIED BY 'NewWebmailDBPass123!';"
mysql -e "FLUSH PRIVILEGES;"
```

### Update webmail config with new DB password
```
vi /etc/roundcubemail/config.inc.php
# Update: $config['db_dsnw'] = 'mysql://user:NEWPASS@localhost/roundcube';
```

## PHASE 10: PHP SECURITY

### Check PHP version and config
```
php -v
php -i | grep 'Configuration File'
cat /etc/php.ini | grep -v '^;' | grep -v '^$'
```

### Disable dangerous functions
```
grep disable_functions /etc/php.ini
```

### Set in /etc/php.ini:
```
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
expose_php = Off
display_errors = Off
file_uploads = On
upload_max_filesize = 10M
```

### Restart PHP-FPM
```
systemctl restart php-fpm
```

## PHASE 11: SELINUX ENFORCEMENT

### Verify SELinux is enforcing
```
getenforce
sestatus
```

### If permissive, enable it NOW
```
setenforce 1
sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
```

### Check for SELinux denials
```
ausearch -m avc -ts recent
sealert -a /var/log/audit/audit.log
```

### Fix common webmail SELinux issues
```
setsebool -P httpd_can_network_connect 1
setsebool -P httpd_can_network_connect_db 1
setsebool -P httpd_can_sendmail 1
restorecon -R /var/www/html
```

## PHASE 12: LOGGING & MONITORING

### Enable auditd
```
systemctl enable --now auditd
```

### Monitor critical files
```
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
auditctl -w /var/www/html -p wa -k webmail_changes
auditctl -w /etc/postfix -p wa -k postfix_changes
auditctl -l
```

### Check recent audit events
```
ausearch -ts recent -i
```

### Monitor mail logs in real-time
```
tail -f /var/log/maillog
journalctl -u postfix -u dovecot -f
```

### Watch for attacks
```
journalctl -u httpd -u nginx --since "10 minutes ago" | grep -E '404|403|POST'
```

## PHASE 13: BACKUP VERIFICATION

### Check for existing backups
```
ls -la /backup /var/backup /opt/backup
crontab -l | grep backup
systemctl list-timers | grep backup
```

### Create emergency backup NOW
```
mkdir -p /backup/$(date +%Y%m%d)
tar -czf /backup/$(date +%Y%m%d)/webmail-config.tar.gz /var/www/html /etc/httpd /etc/roundcubemail
tar -czf /backup/$(date +%Y%m%d)/mail-config.tar.gz /etc/postfix /etc/dovecot
mysqldump --all-databases > /backup/$(date +%Y%m%d)/databases.sql
```

## PHASE 14: PERSISTENCE CHECKS

### Check cron jobs for backdoors
```
crontab -l
ls -la /etc/cron.*
cat /etc/crontab
```

### Check systemd timers
```
systemctl list-timers --all
find /etc/systemd/system -name "*.timer"
```

### Check startup scripts
```
ls -la /etc/rc.d/rc.local
systemctl list-dependencies multi-user.target
```

### Check for suspicious services
```
systemctl list-unit-files --type=service --state=enabled | grep -v '@'
```

## PHASE 15: NETWORK MONITORING

### Continuous connection monitoring
```
watch -n 2 'ss -tnp | grep ESTABLISHED'
```

### Monitor specific ports
```
watch -n 1 'ss -tulpn | grep -E ":80|:443|:25|:143"'
```

### Capture suspicious traffic (if needed)
```
tcpdump -i any -n port 25 -w /tmp/smtp.pcap
tcpdump -i any -n port 80 or port 443 -w /tmp/web.pcap
```

## PHASE 16: INCIDENT RESPONSE

### If compromised, document everything
```
date > /tmp/incident_$(date +%s).log
ps auxf >> /tmp/incident_$(date +%s).log
ss -tulpn >> /tmp/incident_$(date +%s).log
last -20 >> /tmp/incident_$(date +%s).log
```

### Preserve evidence
```
tar -czf /backup/forensics-$(date +%s).tar.gz /var/log /tmp/incident*.log
```

### Isolate if necessary
```
firewall-cmd --panic-on  # BLOCKS ALL TRAFFIC
# To restore: firewall-cmd --panic-off
```

## QUICK WIN CHECKLIST

- [ ] All passwords changed
- [ ] Firewall locked down to required ports only
- [ ] SELinux enforcing
- [ ] Web root permissions correct (755 dirs, 644 files)
- [ ] Postfix relay locked down
- [ ] PHP dangerous functions disabled
- [ ] Database root password changed
- [ ] Webmail config updated
- [ ] No suspicious processes running
- [ ] Audit logging enabled
- [ ] Backup created
- [ ] All services restarted with hardened configs
- [ ] Active monitoring in place

## SCORING ENGINE SURVIVAL

### Keep services UP
```
systemctl status httpd postfix dovecot
curl http://localhost
telnet localhost 25
```

### Auto-restart on failure
```
systemctl edit httpd
# Add:
# [Service]
# Restart=always
# RestartSec=5s

systemctl edit postfix dovecot --full  # Same for all services
```

### Monitor service health
```
watch -n 5 'systemctl is-active httpd postfix dovecot'
```