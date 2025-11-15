# CCDC Webmail Enumeration Kill Chain - Fedora 42

## PHASE 0: BASELINE INFORMATION (30 seconds)

### Who am I? Where am I?
```
whoami
id
hostname
hostname -f
cat /etc/fedora-release
uname -a
```

### Current time and uptime
```
date
timedatectl
uptime
```

### Who else is here?
```
w
who
last -20
lastlog | grep -v "Never"
```

### My network identity
```
ip addr show
ip route show
cat /etc/resolv.conf
```

## PHASE 1: RUNNING SERVICES ENUMERATION

### All active services
```
systemctl list-units --type=service --state=running
systemctl list-units --type=service --state=running --no-pager
```

### Enabled services (what starts at boot)
```
systemctl list-unit-files --type=service --state=enabled
```

### Failed services (potential problems)
```
systemctl --failed
systemctl list-units --state=failed
```

### Service dependencies
```
systemctl list-dependencies multi-user.target
systemctl list-dependencies graphical.target
```

## PHASE 2: NETWORK ENUMERATION

### All listening ports and services
```
ss -tulpn
ss -tulpn | column -t
netstat -tulpn
```

### All TCP/UDP connections
```
ss -tupan
ss -tupan | grep ESTABLISHED
ss -tupan | grep LISTEN
```

### Listening ports only (clean view)
```
lsof -i -P -n | grep LISTEN
```

### Specific port checks
```
ss -tlnp | grep :80
ss -tlnp | grep :443
ss -tlnp | grep :25
ss -tlnp | grep :587
ss -tlnp | grep :143
ss -tlnp | grep :993
ss -tlnp | grep :110
ss -tlnp | grep :995
ss -tlnp | grep :3306
ss -tlnp | grep :5432
```

### Active connections with process info
```
lsof -i
lsof -i TCP
lsof -i UDP
```

### Network interfaces details
```
ip link show
ip addr show
ifconfig -a
```

### Routing table
```
ip route show
route -n
```

### ARP cache (connected devices)
```
ip neigh show
arp -a
```

## PHASE 3: PROCESS ENUMERATION

### All processes (tree view)
```
ps auxf
ps auxf --forest
pstree -p
```

### Processes by CPU usage
```
ps aux --sort=-%cpu | head -20
top -b -n 1 | head -20
```

### Processes by memory usage
```
ps aux --sort=-%mem | head -20
```

### Processes by user
```
ps aux | awk '{print $1}' | sort | uniq -c | sort -rn
ps -u root
ps -u apache
ps -u mysql
ps -u postfix
ps -u dovecot
```

### Processes listening on network
```
lsof -i -n -P
```

### All open files
```
lsof | wc -l
lsof -u root | head -50
```

## PHASE 4: WEB SERVER ENUMERATION

### Identify web server type
```
systemctl status httpd
systemctl status nginx
systemctl status apache2
ps aux | grep -E 'httpd|nginx|apache'
```

### Web server version
```
httpd -v
nginx -v
apachectl -v
```

### Web server configuration test
```
httpd -t
nginx -t
apachectl -S
```

### Configuration files location
```
ls -la /etc/httpd/
ls -la /etc/nginx/
ls -la /etc/apache2/
```

### Main config content
```
cat /etc/httpd/conf/httpd.conf | grep -v '^#' | grep -v '^$'
cat /etc/nginx/nginx.conf | grep -v '^#' | grep -v '^$'
```

### Virtual hosts
```
ls -la /etc/httpd/conf.d/
cat /etc/httpd/conf.d/*.conf
ls -la /etc/nginx/conf.d/
ls -la /etc/nginx/sites-enabled/
```

### Document root enumeration
```
ls -la /var/www/
ls -la /var/www/html/
ls -la /usr/share/nginx/html/
tree -L 2 /var/www/html/
find /var/www -type f -name "*.php" | head -20
```

### Web server modules
```
httpd -M
nginx -V
apachectl -M
ls -la /etc/httpd/conf.modules.d/
```

### SSL/TLS certificates
```
ls -la /etc/pki/tls/certs/
ls -la /etc/pki/tls/private/
ls -la /etc/letsencrypt/
```

### Access and error logs
```
ls -la /var/log/httpd/
ls -la /var/log/nginx/
tail -20 /var/log/httpd/access_log
tail -20 /var/log/httpd/error_log
```

## PHASE 5: MAIL SERVER ENUMERATION

### Mail transfer agent (MTA)
```
systemctl status postfix
systemctl status sendmail
ps aux | grep -E 'postfix|sendmail'
```

### Postfix version and configuration
```
postconf | head -20
postconf -n
postconf mail_version
```

### Postfix main config
```
cat /etc/postfix/main.cf | grep -v '^#' | grep -v '^$'
```

### Postfix critical settings
```
postconf | grep mynetworks
postconf | grep relay
postconf | grep mydestination
postconf | grep myhostname
postconf | grep inet_interfaces
```

### Mail queue status
```
mailq
postqueue -p
postqueue -j
```

### SASL authentication
```
systemctl status saslauthd
postconf | grep sasl
```

### IMAP/POP3 server
```
systemctl status dovecot
systemctl status courier-imap
ps aux | grep -E 'dovecot|courier'
```

### Dovecot version
```
dovecot --version
doveadm --version
```

### Dovecot configuration
```
doveconf -n
doveconf | grep -E 'protocols|ssl|auth'
```

### Dovecot config files
```
ls -la /etc/dovecot/
ls -la /etc/dovecot/conf.d/
cat /etc/dovecot/dovecot.conf | grep -v '^#' | grep -v '^$'
```

### Active mail connections
```
doveadm who
ss -tnp | grep -E ':25|:587|:465|:143|:993|:110|:995'
```

### Mail logs
```
tail -50 /var/log/maillog
journalctl -u postfix --no-pager -n 50
journalctl -u dovecot --no-pager -n 50
```

## PHASE 6: WEBMAIL APPLICATION ENUMERATION

### Find webmail installations
```
find /var/www -name "*roundcube*" 2>/dev/null
find /var/www -name "*squirrelmail*" 2>/dev/null
find /var/www -name "*horde*" 2>/dev/null
find /usr/share -name "*roundcube*" 2>/dev/null
find /usr/share -name "*webmail*" 2>/dev/null
```

### Roundcube specific
```
ls -la /usr/share/roundcubemail/
ls -la /etc/roundcubemail/
cat /etc/roundcubemail/config.inc.php | grep -v '^//' | grep -v '^$'
```

### SquirrelMail specific
```
ls -la /usr/share/squirrelmail/
cat /etc/squirrelmail/config.php | grep -v '^//' | grep -v '^$'
```

### Web application permissions
```
ls -la /var/www/html/
find /var/www/html -type f -perm -002
find /var/www/html -type d -perm -002
```

### Recently modified web files
```
find /var/www -type f -mtime -1
find /var/www -type f -mtime -7
```

### PHP files in web root
```
find /var/www/html -name "*.php" -type f
```

## PHASE 7: PHP ENUMERATION

### PHP version and status
```
php -v
php -i | grep "PHP Version"
systemctl status php-fpm
ps aux | grep php-fpm
```

### PHP configuration files
```
php -i | grep "Configuration File"
ls -la /etc/php.ini
ls -la /etc/php.d/
ls -la /etc/php-fpm.d/
```

### PHP modules loaded
```
php -m
php -m | sort
```

### PHP-FPM configuration
```
cat /etc/php-fpm.conf | grep -v '^;' | grep -v '^$'
ls -la /etc/php-fpm.d/
cat /etc/php-fpm.d/www.conf | grep -v '^;' | grep -v '^$'
```

### PHP settings
```
php -i | grep -E 'disable_functions|expose_php|display_errors|upload_max_filesize|post_max_size'
cat /etc/php.ini | grep disable_functions
cat /etc/php.ini | grep expose_php
```

### PHP-FPM pools
```
ls -la /var/run/php-fpm/
```

## PHASE 8: DATABASE ENUMERATION

### Identify database server
```
systemctl status mariadb
systemctl status mysql
systemctl status postgresql
ps aux | grep -E 'mysql|mariadb|postgres'
```

### MySQL/MariaDB version
```
mysql --version
mysqld --version
```

### Database port check
```
ss -tlnp | grep 3306
ss -tlnp | grep 5432
```

### MySQL/MariaDB processes
```
ps aux | grep mysql
mysqladmin version
mysqladmin status
```

### Database configuration
```
ls -la /etc/my.cnf
ls -la /etc/my.cnf.d/
cat /etc/my.cnf | grep -v '^#' | grep -v '^$'
```

### PostgreSQL configuration (if applicable)
```
ls -la /var/lib/pgsql/
ps aux | grep postgres
```

### Database data directory
```
ls -la /var/lib/mysql/
ls -la /var/lib/pgsql/
du -sh /var/lib/mysql/
```

## PHASE 9: USER & AUTHENTICATION ENUMERATION

### All local users
```
cat /etc/passwd
cat /etc/passwd | grep -v nologin | grep -v false
getent passwd
```

### Users with login shells
```
cat /etc/passwd | grep -v '/nologin' | grep -v '/false'
```

### User groups
```
cat /etc/group
getent group
```

### Sudo privileges
```
cat /etc/sudoers | grep -v '^#' | grep -v '^$'
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/*
```

### Shadow file permissions
```
ls -la /etc/shadow
ls -la /etc/passwd
```

### Recent authentication
```
last -20
lastb | head -20
lastlog
```

### Currently logged in
```
who
w
users
```

### SSH configuration
```
cat /etc/ssh/sshd_config | grep -v '^#' | grep -v '^$'
sshd -T
```

### SSH keys
```
ls -la ~/.ssh/
cat ~/.ssh/authorized_keys
find /home -name "authorized_keys" 2>/dev/null
```

## PHASE 10: FIREWALL ENUMERATION

### Firewalld status
```
systemctl status firewalld
firewall-cmd --state
```

### Active zones
```
firewall-cmd --get-active-zones
firewall-cmd --get-default-zone
```

### Zone configuration
```
firewall-cmd --list-all
firewall-cmd --zone=public --list-all
firewall-cmd --zone=public --list-services
firewall-cmd --zone=public --list-ports
```

### All zones
```
firewall-cmd --list-all-zones
```

### Rich rules
```
firewall-cmd --list-rich-rules
```

### IPTables rules (low level)
```
iptables -L -n -v
iptables -L INPUT -n -v
iptables -L OUTPUT -n -v
iptables -t nat -L -n -v
```

### IP6Tables
```
ip6tables -L -n -v
```

## PHASE 11: SELINUX ENUMERATION

### SELinux status
```
getenforce
sestatus
sestatus -v
```

### SELinux booleans
```
getsebool -a
getsebool -a | grep http
getsebool -a | grep smtp
getsebool -a | grep mail
```

### SELinux contexts
```
ls -Z /var/www/html/
ps auxZ | grep httpd
ps auxZ | grep postfix
```

### Recent SELinux denials
```
ausearch -m avc -ts recent
sealert -a /var/log/audit/audit.log | tail -50
```

### SELinux modules
```
semodule -l
semodule -l | grep -E 'http|mail|post'
```

## PHASE 12: SYSTEM ENUMERATION

### Kernel and OS
```
uname -a
cat /etc/os-release
cat /etc/fedora-release
hostnamectl
```

### Kernel modules
```
lsmod
lsmod | wc -l
```

### System resources
```
free -h
df -h
df -i
lsblk
```

### CPU information
```
lscpu
cat /proc/cpuinfo | grep "model name" | head -1
nproc
```

### Memory information
```
cat /proc/meminfo | head -20
vmstat
```

### Disk usage
```
du -sh /var/www/
du -sh /var/lib/mysql/
du -sh /var/spool/mail/
du -sh /home/
```

### Mount points
```
mount
cat /etc/fstab
findmnt
```

### Block devices
```
lsblk -f
blkid
```

## PHASE 13: PACKAGE & UPDATE ENUMERATION

### Installed packages count
```
rpm -qa | wc -l
dnf list installed | wc -l
```

### Web/mail related packages
```
rpm -qa | grep -E 'httpd|nginx|php|postfix|dovecot|mysql|mariadb|roundcube'
```

### Package versions
```
rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}\n' | grep -E 'httpd|nginx|php|postfix|dovecot'
```

### Available updates
```
dnf check-update
dnf check-update --security
```

### Update history
```
dnf history
dnf history list
```

### Repository configuration
```
dnf repolist
ls -la /etc/yum.repos.d/
```

## PHASE 14: LOG ENUMERATION

### All log files
```
ls -lah /var/log/
du -sh /var/log/*
```

### System logs
```
journalctl --no-pager -n 50
journalctl -p err -b
journalctl -p crit -b
```

### Web server logs
```
ls -la /var/log/httpd/
ls -la /var/log/nginx/
tail -20 /var/log/httpd/access_log
tail -20 /var/log/httpd/error_log
```

### Mail logs
```
tail -50 /var/log/maillog
journalctl -u postfix -n 50
journalctl -u dovecot -n 50
```

### Authentication logs
```
tail -50 /var/log/secure
journalctl -u sshd -n 50
```

### Audit logs
```
systemctl status auditd
ausearch -ts recent | head -50
auditctl -l
```

### Journal disk usage
```
journalctl --disk-usage
```

## PHASE 15: SCHEDULED TASKS ENUMERATION

### Cron jobs
```
crontab -l
ls -la /etc/cron.*
cat /etc/crontab
ls -la /var/spool/cron/
```

### User cron jobs
```
for user in $(cat /etc/passwd | cut -d: -f1); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done
```

### Systemd timers
```
systemctl list-timers --all
systemctl list-timers --all --no-pager
```

### At jobs
```
atq
ls -la /var/spool/at/
```

## PHASE 16: SECURITY ENUMERATION

### SUID/SGID files
```
find / -perm -4000 -type f 2>/dev/null | head -50
find / -perm -2000 -type f 2>/dev/null | head -50
```

### World-writable files
```
find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -50
```

### World-writable directories
```
find / -xdev -type d -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -50
```

### Files with capabilities
```
getcap -r / 2>/dev/null
```

### Files in /tmp and /dev/shm
```
ls -la /tmp/
ls -la /dev/shm/
find /tmp -type f
```

### Suspicious processes from /tmp
```
ps aux | grep -E '/tmp|/dev/shm'
lsof +D /tmp
```

### Listening on non-standard ports
```
ss -tulpn | grep -v -E ':22|:80|:443|:25|:587|:143|:993|:110|:995|:3306'
```

## ENUMERATION SUMMARY COMMAND

### One-liner for quick overview
```
echo "=== HOST ==="; hostname; ip addr show | grep inet; echo "=== SERVICES ==="; systemctl list-units --type=service --state=running --no-pager | grep -E 'httpd|nginx|postfix|dovecot|php|mysql|mariadb'; echo "=== PORTS ==="; ss -tulpn | grep LISTEN; echo "=== USERS ==="; w
```