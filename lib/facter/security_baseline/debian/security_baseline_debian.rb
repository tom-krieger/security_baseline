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
require 'facter/security_baseline/common/trim_string'
require 'facter/security_baseline/common/check_puppet_postrun_command'
require 'pp'

def security_baseline_debian(os, _distid, _release)
  security_baseline = {}

  services = ['autofs', 'avahi-daemon', 'cups', 'dhcpd', 'named', 'dovecot', 'httpd', 'ldap', 'ypserv', 'ntalk', 'rhnsd', 'rsyncd', 'smb',
              'snmpd', 'squid', 'telnet.socket', 'tftp.socket', 'vsftpd', 'xinetd', 'sshd', 'crond']
  packages = { 'iptables' => '-q',
               'openldap-clients' => '-q',
               'mcstrans' => '-q',
               'prelink' => '-q',
               'rsh' => '-q',
               'libselinux' => '-q',
               'setroubleshoot' => '-q',
               'talk' => '-q',
               'tcp_wrappers' => '-q',
               'telnet' => '-q',
               'ypbind' => '-q',
               'openbsd-inetd' => '-s' }
  modules = ['dccp', 'freevxfs', 'hfs', 'hfsplus', 'jffs2', 'rds', 'sctp', 'squashfs', 'tipc', 'udf']
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
  security_baseline[:sysctl] = read_facts_sysctl(sysctl_values)
  security_baseline[:aide] = read_facts_aide(os)

  selinux = {}
  val = Facter::Core::Execution.exec('grep "^\s*linux" /boot/grub/grub.cfg')
  selinux['bootloader'] = check_value_boolean(val, true)
  security_baseline[:selinux] = selinux

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
  mounted = Facter::Core::Execution.exec('mount | grep /home')
  home['nodev'] = check_value_regex(mounted, 'nodev')
  partitions['home'] = home

  tmp = {}
  tmp['partition'] = Facter::Core::Execution.exec('mount | grep "on /tmp "|awk \'{print $3;}\'')
  mounted = Facter::Core::Execution.exec('mount | grep "/tmp "|awk \'{print $3;}\'')
  tmp['nodev'] = check_value_regex(mounted, 'nodev')
  tmp['noexec'] = check_value_regex(mounted, 'noexec')
  tmp['nosuid'] = check_value_regex(mounted, 'nosuid')
  partitions['tmp'] = tmp

  var_tmp = {}
  var_tmp['partition'] = Facter::Core::Execution.exec('mount | grep " on /var/tmp "|awk \'{print $3;}\'')
  mounted = Facter::Core::Execution.exec('mount | grep /var/tmp')
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

  security_baseline
end
