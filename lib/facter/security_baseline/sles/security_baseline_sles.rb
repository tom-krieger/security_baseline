# frozen_string_literal: true

require 'facter/security_baseline/common/check_service_enabled'
require 'facter/security_baseline/common/check_package_installed'
require 'facter/security_baseline/common/check_kernel_module'
require 'facter/security_baseline/common/read_duplicate_groups'
require 'facter/security_baseline/common/read_duplicate_users'
require 'facter/security_baseline/common/read_sysctl_value'
require 'facter/security_baseline/common/read_facts_kernel_modules'
require 'facter/security_baseline/common/read_facts_packages_installed'
require 'facter/security_baseline/common/read_facts_services_enabled'
require 'facter/security_baseline/common/read_facts_xinetd_services'
require 'facter/security_baseline/common/read_facts_sysctl'
require 'facter/security_baseline/common/read_facts_aide'
require 'facter/security_baseline/common/check_value_string'
require 'facter/security_baseline/common/check_value_integer'
require 'facter/security_baseline/common/check_value_boolean'
require 'facter/security_baseline/common/check_value_regex'
require 'facter/security_baseline/common/read_file_stats'
require 'facter/security_baseline/common/read_local_users'
require 'facter/security_baseline/common/read_iptables_rules'
require 'facter/security_baseline/common/trim_string'
require 'facter/security_baseline/common/check_puppet_postrun_command'
require 'facter/security_baseline/common/check_values_expected'
require 'facter/security_baseline/common/read_sshd_config'
require 'facter/security_baseline/common/check_cron_restrict'
require 'facter/security_baseline/common/check_ntp'
require 'facter/security_baseline/common/check_chrony'
require 'pp'

def security_baseline_sles(os, _distid, _release)
  security_baseline = {}
  arch = Facter.value(:architecture)

  services = ['autofs', 'avahi-daemon', 'cups', 'dhcpd', 'named', 'dovecot', 'apache2', 'slapd', 'ypserv', 'ntalk', 'rhnsd', 'rsyncd', 'smb',
              'snmpd', 'squid', 'telnet.socket', 'tftp.socket', 'vsftpd', 'xinetd', 'sshd', 'cron', 'telnet']
  packages = { 'iptables' => '-q',
               'openldap-clients' => '-q',
               'logrotate' => '-q',
               'mcstrans' => '-q',
               'prelink' => '-q',
               'rsh' => '-q',
               'libselinux1' => '-q',
               'selinux-policy' => '-q',
               'libapparmor1' => '-q',
               'apparmor-utils' => '-q',
               'libpwquality1' => '-q',
               'setroubleshoot' => '-q',
               'talk' => '-q',
               'tcpd' => '-q',
               'telnet' => '-q',
               'ypbind' => '-q' }
  modules = ['cramfs', 'dccp', 'freevxfs', 'hfs', 'hfsplus', 'jffs2', 'rds', 'sctp', 'squashfs', 'tipc', 'udf', 'vfat']
  xinetd_services = ['echo', 'echo-udp', 'time', 'time-udp', 'chargen', 'chargen-udp', 'tftp', 'tftp-udp', 'daytime', 'daytime-udp', 'discard', 'discard-udp']
  sysctl_values = ['net.ipv4.ip_forward', 'net.ipv4.conf.all.send_redirects', 'net.ipv4.conf.default.send_redirects',
                   'net.ipv4.conf.all.accept_source_route', 'net.ipv4.conf.default.accept_source_route', 'net.ipv4.conf.all.accept_redirects',
                   'net.ipv4.conf.default.accept_redirects', 'net.ipv4.conf.all.secure_redirects', 'net.ipv4.conf.all.log_martians',
                   'net.ipv4.conf.default.log_martians', 'net.ipv4.icmp_echo_ignore_broadcasts', 'net.ipv4.icmp_ignore_bogus_error_responses',
                   'net.ipv4.conf.all.rp_filter', 'net.ipv4.conf.default.rp_filter', 'net.ipv4.tcp_syncookies',
                   'net.ipv6.conf.all.accept_ra', 'net.ipv6.conf.default.accept_ra', 'net.ipv6.conf.all.accept_redirects',
                   'net.ipv6.conf.default.accept_redirects', 'net.ipv6.conf.all.disable_ipv6', 'net.ipv6.conf.default.disable_ipv6',
                   'kernel.randomize_va_space', 'fs.suid_dumpable']

  security_baseline['puppet_agent_postrun'] = check_puppet_postrun_command
  security_baseline[:kernel_modules] = read_facts_kernel_modules(modules)
  security_baseline[:packages_installed] = read_facts_packages_installed(packages)
  security_baseline[:services_enabled] = read_facts_services_enabled(services)

  security_baseline[:xinetd_services] = read_facts_xinetd_services(xinetd_services)
  security_baseline[:sysctl] = read_facts_sysctl(sysctl_values)
  security_baseline[:aide] = read_facts_aide(os)

  selinux = {}
  val = Facter::Core::Execution.exec('grep "^\s*linux" /boot/grub2/grub.cfg | grep -e "selinux.*=.*0" -e "enforcing.*=.*0"')
  selinux['bootloader'] = (val.nil? || val.empty?)
  security_baseline[:selinux] = selinux

  apparmor = {}
  val = Facter::Core::Execution.exec('grep "^\s*linux" /boot/grub2/grub.cfg | grep "apparmor.*=.*0"')
  apparmor['bootloader'] = (val.nil? || val.empty?)
  val = Facter::Core::Execution.exec('apparmor_status | grep "profiles are loaded"')
  apparmor['profiles'] = if val.nil? || val.empty?
                           0
                         else
                           val.match(%r{(?<profiles>\d+) profiles are loaded})['profiles']
                         end
  val = Facter::Core::Execution.exec('apparmor_status | grep "profiles are in enforce mode"')
  apparmor['profiles_enforced'] = if val.nil? || val.empty?
                                    0
                                  else
                                    val.match(%r{(?<enforce>\d+) profiles are in enforce mode})[:enforce]
                                  end
  val = Facter::Core::Execution.exec('apparmor_status | grep "profiles are in complain mode"')
  apparmor['profiles_complain'] = if val.nil? || val.empty?
                                    0
                                  else
                                    val.match(%r{(?<complain>\d+) profiles are in complain mode})[:complain]
                                  end
  security_baseline[:apparmor] = apparmor

  seval = check_package_installed('libselinux1')
  arval = check_package_installed('libapparmor1')
  security_baseline['access_control'] = if seval || arval
                                          'installed'
                                        else
                                          'none'
                                        end

  partitions = {}
  shm = {}
  mounted = Facter::Core::Execution.exec('mount | grep /dev/shm')
  shm['nodev'] = check_value_regex(mounted, 'nodev')
  shm['noexec'] = check_value_regex(mounted, 'noexec')
  shm['nosuid'] = check_value_regex(mounted, 'nosuid')
  shm['partition'] = Facter::Core::Execution.exec('mount | grep /dev/shm')
  partitions['shm'] = shm

  home = {}
  home['partition'] = Facter::Core::Execution.exec('mount | grep "on /home "|awk \'{print $3;}\'')
  mounted = Facter::Core::Execution.exec('mount | grep "on /home "')
  home['nodev'] = check_value_regex(mounted, 'nodev')
  partitions['home'] = home

  tmp = {}
  tmp['partition'] = Facter::Core::Execution.exec('mount | grep "on /tmp "|awk \'{print $3;}\'')
  mounted = Facter::Core::Execution.exec('mount | grep "on /tmp "')
  tmp['nodev'] = check_value_regex(mounted, 'nodev')
  tmp['noexec'] = check_value_regex(mounted, 'noexec')
  tmp['nosuid'] = check_value_regex(mounted, 'nosuid')
  partitions['tmp'] = tmp

  var_tmp = {}
  var_tmp['partition'] = Facter::Core::Execution.exec('mount | grep " on /var/tmp "|awk \'{print $3;}\'')
  mounted = Facter::Core::Execution.exec('mount | grep "on /var/tmp "')
  var_tmp['nodev'] = check_value_regex(mounted, 'nodev')
  var_tmp['noexec'] = check_value_regex(mounted, 'noexec')
  var_tmp['nosuid'] = check_value_regex(mounted, 'nosuid')
  partitions['var_tmp'] = var_tmp

  var = {}
  var['partition'] = Facter::Core::Execution.exec('mount | grep " on /var "|awk \'{print $3;}\'')
  partitions['var'] = var

  var_log = {}
  var_log['partition'] = Facter::Core::Execution.exec('mount | grep " on /var/log "|awk \'{print $3;}\'')
  partitions['var_log'] = var_log

  var_log_audit = {}
  var_log_audit['partition'] = Facter::Core::Execution.exec('mount | grep "/var/log/audit "|awk \'{print $3;}\'')
  partitions['var_log_audit'] = var_log_audit

  security_baseline[:partitions] = partitions

  zypper = {}
  val =  Facter::Core::Execution.exec('zypper repos | grep -v -e "^#" -e "^-" -e "^$" -e "Repository priorities"')
  if val.nil? || val.empty?
    repos = 'none'
    repocount = 0
  else
    repos = val.split("\n")
    repocount = repos.count
  end
  zypper['repolist_config'] = repocount > 0
  zypper['repolist'] = repos
  value = Facter::Core::Execution.exec('grep "^gpgcheck = on" /etc/zypp/zypp.conf')
  zypper['gpgcheck'] = if value.empty?
                         false
                       elsif value == 'gpgcheck = on'
                         true
                       else
                         false
                       end
  security_baseline[:zypper] = zypper

  x11 = {}
  pkgs = Facter::Core::Execution.exec('rpm -qa xorg-x11* | grep -v xorg-x11-fonts')
  x11['installed'] = if pkgs.nil? || pkgs.empty?
                       false
                     else
                       true
                     end
  security_baseline[:x11] = x11

  single_user_mode = {}
  resc = Facter::Core::Execution.exec('grep /sbin/sulogin /usr/lib/systemd/system/rescue.service')
  single_user_mode['rescue'] = check_value_boolean(resc, false)

  emerg = Facter::Core::Execution.exec('grep /sbin/sulogin /usr/lib/systemd/system/emergency.service')
  single_user_mode['emergency'] = check_value_boolean(emerg, false)

  single_user_mode['status'] = if (single_user_mode['emergency'] == false) || (single_user_mode['rescue'] == false)
                                 false
                               else
                                 true
                               end
  security_baseline[:single_user_mode] = single_user_mode

  issue = {}
  issue['os'] = read_file_stats('/etc/issue')
  issue['os']['content'] = Facter::Core::Execution.exec('egrep \'(\\\v|\\\r|\\\m|\\\s)\' /etc/issue')
  issue['net'] = read_file_stats('/etc/issue.net')
  issue['net']['content'] = Facter::Core::Execution.exec('egrep \'(\\\v|\\\r|\\\m|\\\s)\' /etc/issue.net')
  security_baseline[:issue] = issue

  motd = read_file_stats('/etc/motd')
  motd['content'] = Facter::Core::Execution.exec("egrep '(\\\\v|\\\\r|\\\\m|\\\\s)' /etc/motd")
  security_baseline[:motd] = motd

  val = Facter::Core::Execution.exec("rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'")
  security_baseline[:rpm_gpg_keys] = val
  security_baseline[:rpm_gpg_keys_config] = !(val.nil? || val.empty?)

  val = Facter::Core::Execution.exec("ps -eZ | egrep \"initrc\" | egrep -vw \"tr|ps|egrep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }'")
  security_baseline[:unconfigured_daemons] = check_value_string(val, 'none')

  val = Facter::Core::Execution.exec("df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
  security_baseline[:sticky_ww] = check_value_string(val, 'none')

  val = Facter::Core::Execution.exec('yum check-update --security -q | grep -v ^$')
  security_baseline[:security_patches] = check_value_string(val, 'none')

  security_baseline[:gnome_gdm] = Facter::Core::Execution.exec('rpm -qa | grep gnome') != ''
  val1 = check_value_string(Facter::Core::Execution.exec('grep "user-db:user" /etc/dconf/profile/gdm'), 'none')
  val2 = check_value_string(Facter::Core::Execution.exec('grep "system-db:gdm" /etc/dconf/profile/gdm'), 'none')
  val3 = check_value_string(Facter::Core::Execution.exec('grep "file-db:/usr/share/gdm/greeter-dconf-defaults" /etc/dconf/profile/gdm'), 'none')
  security_baseline[:gnome_gdm_conf] = if (val1 == 'none' || val2 == 'none' || val3 == 'none') && security_baseline[:gnome_gdm]
                                         false
                                       else
                                         true
                                       end

  grub = {}
  val1 = check_value_string(Facter::Core::Execution.exec('grep "^set superusers" /boot/grub2/grub.cfg'), 'none')
  val2 = check_value_string(Facter::Core::Execution.exec('grep "^password" /boot/grub2/grub.cfg'), 'none')
  grub['grub_passwd'] = if val1 == 'none' || val2 == 'none'
                          false
                        else
                          true
                        end
  grub['grub.cfg'] = read_file_stats('/boot/grub2/grub.cfg')
  security_baseline[:grub] = grub

  tcp_wrapper = {}
  hostsallow = read_file_stats('/etc/hosts.allow')
  hostsdeny = read_file_stats('/etc/hosts.deny')
  hostsallow['status'] = File.exist?('/etc/hosts.allow')
  hostsdeny['status'] = File.exist?('/etc/hosts.deny')
  tcp_wrapper['hosts_allow'] = hostsallow
  tcp_wrapper['hosts_deny'] = hostsdeny
  security_baseline[:tcp_wrappers] = tcp_wrapper

  coredumps = {}
  fsdumpable = if security_baseline.key?('sysctl')
                 if security_baseline['sysctl'].key?('fs.suid_dumpable')
                   security_baseline['sysctl']['fs.suid_dumpable']
                 else
                   nil
                 end
               else
                 nil
               end

  coredumps['limits'] = Facter::Core::Execution.exec('grep -h "hard core" /etc/security/limits.conf /etc/security/limits.d/*')
  coredumps['status'] = if coredumps['limits'].empty? || (!fsdumpable.nil? && (security_baseline['sysctl']['fs.suid_dumpable'] != 0))
                          false
                        else
                          true
                        end
  security_baseline[:coredumps] = coredumps

  pkgs = Facter::Core::Execution.exec('rpm -qa xorg-x11* | grep -v xorg-x11-font')
  security_baseline['x11-packages'] = if pkgs.nil? || pkgs.empty?
                                        []
                                      else
                                        pkgs.split("\n")
                                      end

  cron = {}
  cron['/etc/crontab'] = read_file_stats('/etc/crontab')
  cron['/etc/cron.hourly'] = read_file_stats('/etc/cron.hourly')
  cron['/etc/cron.daily'] = read_file_stats('/etc/cron.daily')
  cron['/etc/cron.weekly'] = read_file_stats('/etc/cron.weekly')
  cron['/etc/cron.monthly'] = read_file_stats('/etc/cron.monthly')
  cron['/etc/cron.d'] = read_file_stats('/etc/cron.d')
  cron['/etc/cron.allow'] = read_file_stats('/etc/cron.allow')
  cron['/etc/cron.deny'] = read_file_stats('/etc/cron.deny')
  cron['/etc/at.allow'] = read_file_stats('/etc/at.allow')
  cron['/etc/at.deny'] = read_file_stats('/etc/at.deny')

  cron['restrict'] = check_cron_restrict(cron)
  security_baseline['cron'] = cron

  val = Facter::Core::Execution.exec('dmesg | grep NX')
  security_baseline['nx'] = if check_value_string(val, 'none') =~ %r{protection: active}
                              'protected'
                            else
                              'unprotected'
                            end

  ntpdata = {}
  ntp = check_package_installed('ntp')
  chrony = check_package_installed('chrony')
  ntpdata['ntp_use'] = if ntp != 'none' || chrony != 'none'
                         'used'
                       else
                         'not used'
                       end
  ntpdata.merge!(check_ntp('/etc/ntp.conf', '/etc/sysconfig/ntp'))
  ntpdata.merge!(check_chrony('/etc/chrony.conf', '/etc/sysconfig/chronyd'))
  security_baseline['ntp'] = ntpdata

  security_baseline['sshd'] = read_sshd_config

  pam = {}
  pwquality = {}
  val = Facter::Core::Execution.exec('grep pam_cracklib.so /etc/pam.d/common-password')
  pwquality['try_first_pass'] = val.match(%r{try_first_pass})
  h = val.match(%r{retry\s*=\s*(?<rt>\d+)})
  val = if h.is_a?(Hash)
          h['rt']
        else
          ''
        end
  pwquality['retry'] = check_value_string(val, 'none')
  val = trim_string(Facter::Core::Execution.exec('grep ^minlen /etc/security/pwquality.conf | awk -F = \'{print $2;}\''))
  pwquality['minlen'] = check_value_string(val, 'none')
  val = trim_string(Facter::Core::Execution.exec('grep ^dcredit /etc/security/pwquality.conf | awk -F = \'{print $2;}\''))
  pwquality['dcredit'] = check_value_string(val, 'none')
  val = trim_string(Facter::Core::Execution.exec('grep ^lcredit /etc/security/pwquality.conf | awk -F = \'{print $2;}\''))
  pwquality['lcredit'] = check_value_string(val, 'none')
  val = trim_string(Facter::Core::Execution.exec('grep ^ocredit /etc/security/pwquality.conf | awk -F = \'{print $2;}\''))
  pwquality['ocredit'] = check_value_string(val, 'none')
  val = trim_string(Facter::Core::Execution.exec('grep ^ucredit /etc/security/pwquality.conf | awk -F = \'{print $2;}\''))
  pwquality['ucredit'] = check_value_string(val, 'none')
  pwquality['status'] = if (pwquality['minlen'] == 'none') || (pwquality['minlen'] < '14') ||
                           (pwquality['dcredit'] == 'none') || (pwquality['dcredit'] != '-1') ||
                           (pwquality['lcredit'] == 'none') || (pwquality['lcredit'] != '-1') ||
                           (pwquality['ocredit'] == 'none') || (pwquality['ocredit'] != '-1') ||
                           (pwquality['ucredit'] == 'none') || (pwquality['ucredit'] != '-1') ||
                           (pwquality['retry'] == 'none') || (pwquality['retry'] > 3)
                          false
                        else
                          true
                        end
  val = Facter::Core::Execution.exec('grep pam_tally2\.so /etc/pam.d/common-auth')
  valauth = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec('grep pam_tally2\.so /etc/pam.d/common-account')
  valaccount = check_value_string(val, 'none')
  pwquality['lockout'] = if (valauth == 'none') || (valaccount == 'none')
                           false
                         else
                           true
                         end
  pam['pwquality'] = pwquality
  opasswd = {}
  val1 = Facter::Core::Execution.exec("egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/common-password")[%r{remember=(\d+)}, 0]
  if val1.nil? || val1.empty?
    val1 = 0
  end
  opasswd['status'] = if val1.to_s < '5'
                        false
                      else
                        true
                      end
  pam['opasswd'] = opasswd
  sha = {}
  val = Facter::Core::Execution.exec("egrep '^password\s+required\s+pam_unix.so' /etc/pam.d/common-password")
  sha['status'] = check_value_regex(val, 'sha512')
  pam['sha512'] = sha
  val = Facter::Core::Execution.exec('egrep "^auth\s+required\s+pam_wheel.so\s+use_uid" /etc/pam.d/su')
  pam['wheel'] = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec('grep wheel /etc/group | cut -d : -f 4')
  users = if val.nil? || val.empty?
            []
          else
            val.split(%r{,})
          end
  pam['wheel_users'] = users
  pam['wheel_users_count'] = users.count
  security_baseline['pam'] = pam

  security_baseline['local_users'] = read_local_users
  pw_data = {}
  val = Facter::Core::Execution.exec("grep ^PASS_MAX_DAYS /etc/login.defs | awk '{print $2;}'")
  pw_data['pass_max_days'] = check_value_integer(val, 99_999)
  pw_data['pass_max_days_status'] = if pw_data['pass_max_days'] > 365
                                      true
                                    else
                                      false
                                    end
  val = Facter::Core::Execution.exec("grep ^PASS_MIN_DAYS /etc/login.defs | awk '{print $2;}'")
  pw_data['pass_min_days'] = check_value_string(val, '0')
  pw_data['pass_min_days_status'] = pw_data['pass_min_days'] < '7'
  val = Facter::Core::Execution.exec("grep ^PASS_WARN_AGE /etc/login.defs | awk '{print $2;}'")
  pw_data['pass_warn_age'] = check_value_string(val, '0')
  pw_data['pass_warn_age_status'] = pw_data['pass_warn_age'] < '7'
  val = Facter::Core::Execution.exec('useradd -D | grep INACTIVE | cut -f 2 -d =')
  pw_data['inactive'] = check_value_string(val, '-1').to_i
  pw_data['inactive_status'] = pw_data['inactive'] < 30
  ret = false
  security_baseline['local_users'].each do |_user, data|
    unless data['password_date_valid']
      ret = true
    end
  end
  pw_data['pw_change_in_future'] = ret
  security_baseline['pw_data'] = pw_data

  accounts = {}
  wrong_shell = []
  cmd = "egrep -v \"^\/+\" /etc/passwd | awk -F: '($1!=\"root\" && $1!=\"sync\" && $1!=\"shutdown\" && $1!=\"halt\" && $3<1000 && $7!=\"/sbin/nologin\" && $7!=\"/bin/false\") {print}'"
  val = Facter::Core::Execution.exec(cmd)
  unless val.nil? || val.empty?
    val.split("\n").each do |line|
      data = line.split(%r{:})
      wrong_shell.push(data[0])
    end
  end
  accounts['no_shell_nologin'] = wrong_shell
  accounts['no_shell_nologin_count'] = wrong_shell.count
  val = Facter::Core::Execution.exec('grep "^root:" /etc/passwd | cut -f4 -d:')
  accounts['root_gid'] = check_value_string(val, 'none')
  security_baseline['accounts'] = accounts

  ret = false
  val = Facter::Core::Execution.exec('grep -h "umask" /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh')
  if val.nil? || val.empty?
    ret = true
  else
    val.split("\n").each do |line|
      next unless line =~ %r{umask\s*\d+}
      line.strip!
      data = line.split(%r{\s+})
      mask = data[1]
      if mask.to_s < '027'
        ret = true
      end
    end
  end
  security_baseline['umask'] = ret

  val = Facter::Core::Execution.exec('grep -h "^TMOUT" /etc/bash.bashrc /etc/profile')
  if val.nil? || val.empty?
    ret = true
  else
    val.split("\n").each do |line|
      next unless line =~ %r{TIMEOUT=\d+}
      line.strip!
      data = line.split(%r{=})
      timeout = data[1]
      if timeout.to_s > '900'
        ret = true
      end
    end
  end
  security_baseline['timeout'] = ret

  file_permissions = {}
  file_permissions['passwd'] = read_file_stats('/etc/passwd')
  file_permissions['shadow'] = read_file_stats('/etc/shadow')
  file_permissions['group'] = read_file_stats('/etc/group')
  file_permissions['gshadow'] = read_file_stats('/etc/gshadow')
  file_permissions['passwd-'] = read_file_stats('/etc/passwd-')
  file_permissions['shadow-'] = read_file_stats('/etc/shadow-')
  file_permissions['group-'] = read_file_stats('/etc/group-')
  file_permissions['gshadow-'] = read_file_stats('/etc/gshadow-')

  files = []
  if File.exist?('/root/world-writable-files.txt')
    text = File.open('/root/world-writable-files.txt').read
    text.gsub!(%r{\r\n?}, "\n")
    files = text.split("\n")
  end
  file_permissions['world_writable'] = files
  file_permissions['world_writable_count'] = files.count

  files = []
  if File.exist?('/usr/share/security_baseline/data/system-file-permissions.txt')
    text = File.open('/usr/share/security_baseline/data/system-file-permissions.txt').read
    text.gsub!(%r{\r\n?}, "\n")
    files = text.split("\n")
  end
  file_permissions['system_files'] = files
  file_permissions['system_files_count'] = files.count

  files = []
  if File.exist?('/usr/share/security_baseline/data/unowned_files_user.txt')
    text = File.open('/usr/share/security_baseline/data/unowned_files_user.txt').read
    text.gsub!(%r{\r\n?}, "\n")
    files = text.split("\n")
  end
  file_permissions['unowned'] = files
  file_permissions['unowned_count'] = files.count

  files = []
  if File.exist?('/usr/share/security_baseline/data/unowned_files_group.txt')
    text = File.open('/usr/share/security_baseline/data/unowned_files_group.txt').read
    text.gsub!(%r{\r\n?}, "\n")
    files = text.split("\n")
  end
  file_permissions['ungrouped'] = files
  file_permissions['ungrouped_count'] = files.count

  security_baseline['file_permissions'] = file_permissions

  val = Facter::Core::Execution.exec("cat /etc/shadow | awk -F: \'($2 == \"\" ) { print $1 \" does not have a password \"}\'")
  security_baseline['empty_passwords'] = check_value_string(val, 'none')

  legacy = {}
  val = Facter::Core::Execution.exec("grep '^\+:' /etc/passwd")
  legacy['passwd'] = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec("grep '^\+:' /etc/shadow")
  legacy['shadow'] = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec("grep '^\+:' /etc/group")
  legacy['group'] = check_value_string(val, 'none')
  security_baseline['legacy_plus'] = legacy

  val = Facter::Core::Execution.exec("cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'")
  security_baseline['uid_0'] = check_value_string(val, 'none')

  if File.exist?('/usr/share/security_baseline/bin/root_path_integrity.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/root_path_integrity.sh')
    security_baseline['root_path_integrity'] = check_value_string(val, 'none')
  end

  if File.exist?('/usr/share/security_baseline/bin/check_user_home_dirs.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/check_user_home_dirs.sh')
    security_baseline['user_home_dirs'] = check_value_string(val, 'none')
  end

  if File.exist?('/usr/share/security_baseline/bin/check_home_dir_permissions.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/check_home_dir_permissions.sh')
    security_baseline['home_dir_permissions'] = check_value_string(val, 'none')
  end

  if File.exist?('/usr/share/security_baseline/bin/check_home_dir_owner.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/check_home_dir_owner.sh')
    security_baseline['home_dir_owners'] = check_value_string(val, 'none')
  end

  if File.exist?('/usr/share/security_baseline/bin/check_dot_files_write.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/check_dot_files_write.sh')
    security_baseline['user_dot_file_write'] = check_value_string(val, 'none')
  end

  if File.exist?('/usr/share/security_baseline/bin/check_forward_files.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/check_forward_files.sh')
    security_baseline['forward_files'] = check_value_string(val, 'none')
  end

  if File.exist?('/usr/share/security_baseline/bin/check_netrc_files.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/check_netrc_files.sh')
    security_baseline['netrc_files'] = check_value_string(val, 'none')
  end

  if File.exist?('/usr/share/security_baseline/bin/check_netrc_files_write.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/check_netrc_files_write.sh')
    security_baseline['netrc_files_write'] = check_value_string(val, 'none')
  end

  if File.exist?('/usr/share/security_baseline/bin/check_rhosts_files.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/check_rhosts_files.sh')
    security_baseline['rhosts_files'] = check_value_string(val, 'none')
  end

  if File.exist?('/usr/share/security_baseline/bin/check_passwd_group_exist.sh')
    val = Facter::Core::Execution.exec('/usr/share/security_baseline/bin/check_passwd_group_exist.sh')
    security_baseline['passwd_group'] = check_value_string(val, 'none')
  end

  security_baseline['duplicate_uids'] = check_value_string(read_duplicate_users('uid'), 'none')
  security_baseline['duplicate_users'] = check_value_string(read_duplicate_users('user'), 'none')
  security_baseline['duplicate_gids'] = check_value_string(read_duplicate_groups('gid'), 'none')
  security_baseline['duplicate_groups'] = check_value_string(read_duplicate_groups('group'), 'none')

  auditd = {}
  val = Facter::Core::Execution.exec('grep "^max_log_file\s*=" /etc/audit/auditd.conf | awk -F\'=\' \'{print $2;}\'').strip
  auditd['max_log_file'] = if val.empty? || val.nil?
                             'none'
                           else
                             val.to_i
                           end

  val = Facter::Core::Execution.exec('grep "^space_left_action.*=" /etc/audit/auditd.conf | awk -F\'=\' \'{print $2;}\'').strip
  auditd['space_left_action'] = if val.empty? || val.nil?
                                  'none'
                                else
                                  val
                                end

  val = Facter::Core::Execution.exec('grep action_mail_acct /etc/audit/auditd.conf | awk -F\'=\' \'{print $2;}\'').strip
  auditd['action_mail_acct'] = if val.empty? || val.nil?
                                 'none'
                               else
                                 val
                               end

  val = Facter::Core::Execution.exec('grep "^admin_space_left_action.*=" /etc/audit/auditd.conf | awk -F\'=\' \'{print $2;}\'').strip
  auditd['admin_space_left_action'] = if val.empty? || val.nil?
                                        'none'
                                      else
                                        val
                                      end
  auditd['when_full'] = if auditd['admin_space_left_action'] == 'none' ||
                           auditd['action_mail_acct'] == 'none' ||
                           auditd['space_left_action'] == 'none'
                          false
                        else
                          true
                        end
  val = Facter::Core::Execution.exec('grep max_log_file_action /etc/audit/auditd.conf | awk -F\'=\' \'{print $2;}\'').strip
  auditd['max_log_file_action'] = if val.empty? || val.nil?
                                    'none'
                                  else
                                    val
                                  end

  auditd['srv_auditd'] = check_service_is_enabled('auditd')
  val = Facter::Core::Execution.exec('grep "^\s*linux.*audit=1" /boot/grub2/grub.cfg')
  auditd['auditing_process'] = if val.empty? || val.nil?
                                 'none'
                               else
                                 'audit=1'
                               end

  val = Facter::Core::Execution.exec('auditctl -l | grep time-change')
  expected = [
    '-a always,exit -F arch=b32 -S stime,settimeofday,adjtimex -F key=time-change',
    '-a always,exit -F arch=b32 -S clock_settime -F key=time-change',
    '-w /etc/localtime -p wa -k time-change',
  ]
  if arch == 'x86_64'
    expected.push('-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change')
    expected.push('-a always,exit -F arch=b64 -S clock_settime -F key=time-change')
  end
  auditd['time-change'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep identity')
  expected = [
    '-w /etc/group -p wa -k identity',
    '-w /etc/passwd -p wa -k identity',
    '-w /etc/gshadow -p wa -k identity',
    '-w /etc/shadow -p wa -k identity',
    '-w /etc/security/opasswd -p wa -k identity',
  ]
  auditd['identity'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep system-locale')
  expected = [
    '-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale',
    '-w /etc/issue -p wa -k system-locale',
    '-w /etc/issue.net -p wa -k system-locale',
    '-w /etc/hosts -p wa -k system-locale',
    '-w /etc/sysconfig/network -p wa -k system-locale',
    '-w /etc/sysconfig/network-scripts -p wa -k system-locale',
  ]
  if arch == 'x86_64'
    expected.push('-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale')
  end
  auditd['system-locale'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep MAC-policy')
  expected = [
    '-w /etc/selinux -p wa -k MAC-policy',
    '-w /usr/share/selinux -p wa -k MAC-policy',
  ]
  auditd['mac-policy'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep logins')
  expected = [
    '-w /var/log/lastlog -p wa -k logins',
    '-w /var/run/faillock -p wa -k logins',
  ]
  auditd['logins'] = check_values_expected(val, expected, true)

  val = Facter::Core::Execution.exec('auditctl -l | grep session')
  expected = [
    '-w /var/run/utmp -p wa -k session',
  ]
  auditd['session'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep "logins$"')
  expected = [
    '-w /var/log/wtmp -p wa -k logins',
    '-w /var/log/btmp -p wa -k logins',
  ]
  auditd['session-logins'] = check_values_expected(val, expected, true)

  val = Facter::Core::Execution.exec('auditctl -l | grep perm_mod')
  expected = [
    '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod',
    '-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod',
    '-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod',
  ]
  if arch == 'x86_64'
    expected.push('-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod')
    expected.push('-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod')
    expected.push('-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod')
  end
  auditd['perm-mod'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep access')
  expected = [
    '-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access',
    '-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access',
  ]
  if arch == 'x86_64'
    expected.push('-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access')
    expected.push('-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access')
  end
  auditd['access'] = check_values_expected(val, expected)

  rules = {}
  priv_cmds = []
  expected = []
  # Facter.value(:partitions).each do |_part, data|
  #  if (data.key?('mount')) && (data['filesystem'] != 'iso9660') && ! _part.match(%r{^\/dev/loop}) && ! _part.match(%r{^\/dev/mapper\/docker})
  #    mount = data['mount']
  #    cmd = "find #{mount} -xdev \\( -perm -4000 -o -perm -2000 \\) -type f | awk '{print \"-a always,exit -S all -F path=\" $1 \" -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged\"; }'"
  #    rules_raw = Facter::Core::Execution.exec(cmd).split("\n")
  #    priv_cmds.push(rules_raw)
  #    rules[mount] = rules_raw
  #    expected.push(*rules_raw)
  #  end
  # end
  cmd = "find /usr -xdev \\( -perm -4000 -o -perm -2000 \\) -type f | awk '{print \"-a always,exit -S all -F path=\" $1 \" -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged\"; }'"
  rules_raw = Facter::Core::Execution.exec(cmd).split("\n")
  priv_cmds.push(rules_raw)
  rules['/usr'] = rules_raw
  expected.push(*rules_raw)
  expected.uniq!
  auditd['priv-cmds-rules'] = rules
  auditd['priv-cmds-list'] = priv_cmds.uniq

  val = Facter::Core::Execution.exec('auditctl -l | grep "privileged$"')
  auditd['priv-cmds'] = check_values_expected(val, expected, true)

  val = Facter::Core::Execution.exec('auditctl -l | grep "mounts$"')
  expected = [
    '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts',
  ]
  if arch == 'x86_64'
    expected.push('-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts')
  end
  auditd['mounts'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep "delete$"')
  expected = [
    '-a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete',
  ]
  if arch == 'x86_64'
    expected.push('-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete')
  end
  auditd['delete'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep scope')
  expected = [
    '-w /etc/sudoers -p wa -k scope',
    '-w /etc/sudoers.d -p wa -k scope',
  ]
  auditd['scope'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep actions')
  expected = [
    '-w /var/log/sudo.log -p wa -k actions',
  ]
  auditd['actions'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('auditctl -l | grep "modules$"')
  expected = [
    '-w /sbin/insmod -p x -k modules',
    '-w /sbin/rmmod -p x -k modules',
    '-w /sbin/modprobe -p x -k modules',
  ]
  if arch == 'x86_64'
    expected.push('-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules')
  else
    expected.push('-a always,exit -F arch=b32q -S init_module,delete_module -F key=modules')
  end
  auditd['modules'] = check_values_expected(val, expected)

  val = Facter::Core::Execution.exec('grep "^\s*[^#]" /etc/audit/audit.rules | tail -1')
  auditd['immutable'] = if val.empty? || val.nil?
                          false
                        elsif val == '-e 2'
                          true
                        else
                          false
                        end

  security_baseline['auditd'] = auditd

  syslog = {}
  rsyslog = {}
  rsyslog['service'] = check_service_is_enabled('rsyslog')
  rsyslog['package'] = check_package_installed('rsyslog')
  val = Facter::Core::Execution.exec('grep -h ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null')
  unless val.empty? || val.nil?
    val.strip!
    val1 = val.match(%r{FileCreateMode (?<mode>\d+)})[:mode]
  end
  # rsyslog['filepermissions'] = check_value_string(val1, 'none')
  rsyslog['filepermissions'] = val1
  val = Facter::Core::Execution.exec('grep -h "^*.*[^I][^I]*@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null')
  rsyslog['remotesyslog'] = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec("grep -h '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null")
  mod = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec("grep -h '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null")
  port = check_value_string(val, 'none')
  rsyslog['loghost'] = if (mod != 'none') && (port != 'none')
                         true
                       else
                         false
                       end
  syslog['rsyslog'] = rsyslog

  syslog_ng = {}
  syslog_ng['service'] = check_service_is_enabled('syslog-ng')
  syslog_ng['package'] = check_package_installed('syslog-ng')
  val = Facter::Core::Execution.exec('grep -h ^options /etc/syslog-ng/syslog-ng.conf 2>/dev/null').match(%r{perm\((\d+)\)})
  # syslog_ng['filepermissions'] = check_value_string(val, 'none')
  syslog_ng['filepermissions'] = val
  val = Facter::Core::Execution.exec('grep -h destination logserver /etc/syslog-ng/syslog-ng.conf 2>/sdev/null').match(%r{tcp\((.*)\)})
  logserv = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec('grep -h "log.*{.*source(src);.*destination(logserver);.*};" /etc/syslog-ng/syslog-ng.conf 2>/dev/null')
  logsend = check_value_string(val, 'none')
  syslog_ng['remotesyslog'] = if (logserv == 'none') || (logsend == 'none')
                                'none'
                              else
                                logserv
                              end
  val = Facter::Core::Execution.exec('grep -h "source net{.*tcp();.*};" /etc/syslog-ng/syslog-ng.conf 2>/dev/null')
  logsrc = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec('grep -h "destination remote.*{.*file(\"/var/log/remote/\${FULLHOST}-log\");.*};" /etc/syslog-ng/syslog-ng.conf 2>/dev/null')
  logdest = check_value_string(val, 'none')
  val = Facter::Core::Execution.exec('grep -h "log {.*source(net);.*destination(remote);.*};" /etc/syslog-ng/syslog-ng.conf 2>/dev/null')
  log = check_value_string(val, 'none')
  syslog_ng['loghost'] = if (logsrc != 'none') && (logdest != 'none') && (log != 'none')
                           true
                         else
                           false
                         end
  syslog['syslog-ng'] = syslog_ng

  syslog['syslog_installed'] = syslog['rsyslog']['package'] || syslog['syslog-ng']['package']

  logfiles = {}
  log_status = 'ok'
  Facter::Core::Execution.exec('find /var/log -type f').split("\n").each do |logfile|
    stats = read_file_stats(logfile)
    logfiles[logfile] = stats['mode']
    if stats['mode'] != 416
      log_status = 'not ok'
    end
  end
  syslog['logfiles'] = logfiles
  syslog['log_status'] = log_status
  security_baseline['syslog'] = syslog

  valgroup = Facter::Core::Execution.exec('grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group')
  val = if valgroup.nil? || valgroup.empty?
          []
        else
          valgroup.split("\n")
        end
  security_baseline['shadow_group'] = val
  security_baseline['shadow_group_count'] = val.count

  security_baseline['iptables'] = read_iptables_rules('4')
  security_baseline['ip6tables'] = read_iptables_rules('6')

  wlan = []
  cnt = 0
  nw = Facter.value(:networking)
  nw['interfaces'].each do |ifname, _data|
    if ifname =~ %r{wlan}
      cnt += 1
      wlan.push(ifname)
    end
  end
  security_baseline['wlan_interfaces'] = wlan
  security_baseline['wlan_interfaces_count'] = cnt

  val = Facter::Core::Execution.exec('grep "^\s*linux" /boot/grub/grub.cfg | grep  "ipv6.disable=1"')
  security_baseline['grub_ipv6_disabled'] = if val.nil? || val.empty?
                                              false
                                            elsif val =~ %r{ipv6.disable=1}
                                              true
                                            else
                                              false
                                            end

  security_baseline
end
