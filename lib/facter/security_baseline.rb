require 'facter/helpers/check_service_enabled'
require 'facter/helpers/check_package_installed'
require 'facter/helpers/check_kernel_module'
require 'facter/helpers/get_duplicate_groups'
require 'facter/helpers/get_duplicate_users'
require 'facter/helpers/get_sysctl_value'

# frozen_string_literal: true

# security_baseline.rb
# collect facts about the security baseline

Facter.add(:security_baseline) do
  confine kernel: 'Linux'
  setcode do
    security_baseline = {}

    kernel_modules = {}
    modules = ['cramfs', 'dccp', 'freevxfs', 'hfs', 'hfsplus', 'jffs2', 'rds', 'sctp', 'squashfs', 'tipc', 'udf', 'vfat']

    modules.each do |mod|
      kernel_modules[mod] = check_kernel_module(mod)
    end

    security_baseline[:kernel_modules] = kernel_modules

    packages_installed = {}
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
                 'ypbind' => '-q' }

    packages.each do |package, opts|
      packages_installed[package] = check_package_installed(package, opts)
    end

    security_baseline[:packages_installed] = packages_installed

    services_enabled = {}
    services = ['autofs', 'avahi-daemon', 'cups', 'named', 'dovecot', 'httpd', 'ldap', 'ypserv', 'ntalk', 'rhnsd', 'rsyncd', 'smb',
                'snmpd', 'squid', 'telnet.socket', 'tftp.socket', 'vsftpd', 'xinetd']

    services.each do |srv|
      srv_name = "srv_#{srv}"
      services_enabled[srv_name] = check_service_is_enabled(srv)
    end

    rsh = check_service_is_enabled('rsh.socket')
    rlogin = check_service_is_enabled('rlogin.socket')
    rexec = check_service_is_enabled('recex.socket')

    services_enabled['srv_rsh'] = if (rsh == 'enbaled') || (rlogin == 'enabled') || (rexec == 'enabled')
                                    'enabled'
                                  else
                                    'disabled'
                                  end

    nfs = check_service_is_enabled('nfs')
    nfsserver = check_service_is_enabled('nfs-server')
    rpcbind = check_service_is_enabled('rpcbind')

    services_enabled['srv_nfs'] = if (nfs != 'disabled') || (nfsserver != 'disabled') || (rpcbind != 'disabled')
                                    'enabled'
                                  else
                                    'disabled'
                                  end

    security_baseline[:services_enabled] = services_enabled

    xinetd_services = {}
    srvs = ['echo', 'time', 'chargen', 'tftp', 'daytime', 'discard']

    srvs.each do |srv|
      srv_name = "srv_#{srv}"
      xinetd_services[srv_name] = check_xinetd_service(srv)
    end

    security_baseline[:xinetd_services] = xinetd_services

    sysctl = {}
    sysctl['kernel_aslr'] = get_sysctl_value('kernel.randomize_va_space')
    sysctl['fs_dumpable'] = get_sysctl_value('fs.suid_dumpable')

    network_keys = ['net.ipv4.ip_forward', 'net.ipv4.conf.all.send_redirects', 'net.ipv4.conf.default.send_redirects',
                    'net.ipv4.conf.all.accept_source_route', 'net.ipv4.conf.default.accept_source_route', 'net.ipv4.conf.all.accept_redirects',
                    'net.ipv4.conf.default.accept_redirects', 'net.ipv4.conf.all.secure_redirects', 'net.ipv4.conf.all.log_martians',
                    'net.ipv4.conf.default.log_martians', 'net.ipv4.icmp_echo_ignore_broadcasts', 'net.ipv4.icmp_ignore_bogus_error_responses',
                    'net.ipv4.conf.all.rp_filter', 'net.ipv4.conf.default.rp_filter', 'net.ipv4.tcp_syncookies',
                    'net.ipv6.conf.all.accept_ra', 'net.ipv6.conf.default.accept_ra', 'net.ipv6.conf.all.accept_redirects',
                    'net.ipv6.conf.default.accept_redirects', 'net.ipv6.conf.all.disable_ipv6', 'net.ipv6.conf.default.disable_ipv6']

    network_keys.each do |key|
      sysctl[key] = get_sysctl_value(key)
    end

    security_baseline[:sysctl] = sysctl

    aide = {}

    cronentry = Facter::Core::Execution.exec('crontab -u root -l | grep aide')
    fileentry = Facter::Core::Execution.exec('grep -rh aide /etc/cron.* /etc/crontab')

    if cronentry.empty? && fileentry.empty?
      aide['cron'] = 'undef'
    else
      unless cronentry.empty?
        aide['cron'] = cronentry
      end
      unless fileentry.empty?
        aide['cron'] = fileentry
      end
    end

    val = Facter::Core::Execution.exec("rpm -q --queryformat '%{version}' aide")
    aide['version'] = if val.empty? || val =~ %r{not installed}
                        'not installed'
                      else
                        val
                      end

    security_baseline[:aide] = aide

    selinux = {}
    val = Facter::Core::Execution.exec('grep "^\s*linux" /boot/grub2/grub.cfg | grep -e "selinux.*=.*0" -e "enforcing.*=.*0"')
    selinux['bootloader'] = if val.empty?
                              true
                            else
                              false
                            end

    security_baseline[:selinux] = selinux

    partitions = {}
    shm = {}
    mounted = Facter::Core::Execution.exec('mount | grep /dev/shm')
    shm['nodev'] = if mounted.match?(%r{nodev})
                     true
                   else
                     false
                   end
    shm['noexec'] = if mounted.match?(%r{noexec})
                      true
                    else
                      false
                    end
    shm['nosuid'] = if mounted.match?(%r{nosuid})
                      true
                    else
                      false
                    end
    shm['partition'] = Facter::Core::Execution.exec('mount | grep /dev/shm')
    partitions['shm'] = shm

    home = {}
    home['partition'] = Facter::Core::Execution.exec('mount | grep /home')
    mounted = Facter::Core::Execution.exec('mount | grep /home')
    home['nodev'] = if mounted.match?(%r{nodev})
                      true
                    else
                      false
                    end
    partitions['home'] = home

    tmp = {}
    tmp['partition'] = Facter::Core::Execution.exec('mount | grep "/tmp "')
    mounted = Facter::Core::Execution.exec('mount | grep /tmp')
    tmp['nodev'] = if mounted.match?(%r{nodev})
                     true
                   else
                     false
                   end
    tmp['noexec'] = if mounted.match?(%r{noexec})
                      true
                    else
                      false
                    end
    tmp['nosuid'] = if mounted.match?(%r{nosuid})
                      true
                    else
                      false
                    end

    partitions['tmp'] = tmp

    var_tmp = {}
    var_tmp['partition'] = Facter::Core::Execution.exec('mount | grep "/var/tmp "')
    mounted = Facter::Core::Execution.exec('mount | grep /var/tmp')
    var_tmp['nodev'] = if mounted.match?(%r{nodev})
                         true
                       else
                         false
                       end
    var_tmp['noexec'] = if mounted.match?(%r{noexec})
                          true
                        else
                          false
                        end
    var_tmp['nosuid'] = if mounted.match?(%r{nosuid})
                          true
                        else
                          false
                        end

    partitions['var_tmp'] = var_tmp

    var = {}
    var['partition'] = Facter::Core::Execution.exec('mount | grep "/var "')
    partitions['var'] = var

    var_log = {}
    var_log['partition'] = Facter::Core::Execution.exec('mount | grep "/var/log "')
    partitions['var_log'] = var_log

    var_log_audit = {}
    var_log_audit['partition'] = Facter::Core::Execution.exec('mount | grep "/var/log/audit "')
    partitions['var_log_audit'] = var_log_audit

    security_baseline[:partitions] = partitions

    yum = {}
    yum['repolist'] = Facter::Core::Execution.exec('yum repolist')
    value = Facter::Core::Execution.exec('grep ^gpgcheck /etc/yum.conf')
    yum['gpgcheck'] = if value.empty?
                        false
                      elsif value == 'gpgcheck=1'
                        true
                      else
                        false
                      end

    security_baseline[:yum] = yum

    groups = {}
    groups['duplicate_gid'] = get_duplicate_groups('gid')
    groups['duplicate_group'] = get_duplicate_groups('group')
    security_baseline[:groups] = groups

    users = {}
    users['duplicate_uid'] = get_duplicate_users('uid')
    users['duplidate_user'] = get_duplicate_users('user')
    security_baseline[:users] = users

    x11 = {}
    pkgs = Facter::Core::Execution.exec('rpm -qa xorg-x11*')
    x11['installed'] = pkgs.split("\n")

    security_baseline[:x11] = x11

    single_user_mode = {}

    resc = Facter::Core::Execution.exec('grep /sbin/sulogin /usr/lib/systemd/system/rescue.service')
    single_user_mode['rescue'] = if resc.empty?
                                   false
                                 else
                                   true
                                 end

    emerg = Facter::Core::Execution.exec('grep /sbin/sulogin /usr/lib/systemd/system/emergency.service')
    single_user_mode['emergency'] = if emerg.empty?
                                      false
                                    else
                                      true
                                    end

    single_user_mode['status'] = if (single_user_mode['emergency'] == false) || (single_user_mode['rescue'] == false)
                                   false
                                 else
                                   true
                                 end
    security_baseline[:single_user_mode] = single_user_mode

    issue = {}
    issue['os'] = Facter::Core::Execution.exec('egrep \'(\\\v|\\\r|\\\m|\\\s)\' /etc/issue')
    issue['net'] = Facter::Core::Execution.exec('egrep \'(\\\v|\\\r|\\\m|\\\s)\' /etc/issue.net')
    security_baseline[:issue] = issue

    security_baseline[:motd] = Facter::Core::Execution.exec("egrep '(\\\\v|\\\\r|\\\\m|\\\\s)' /etc/motd")
    security_baseline[:rpm_gpg_keys] = Facter::Core::Execution.exec("rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'")
    security_baseline[:unconfigured_daemons] = Facter::Core::Execution.exec("ps -eZ | egrep \"initrc\" | egrep -vw \"tr|ps|egrep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }'")
    security_baseline[:sticky_ww] = Facter::Core::Execution.exec("df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null")
    security_baseline[:security_patches] = Facter::Core::Execution.exec('yum check-update --security -q | grep -v ^$')
    security_baseline[:gnome_gdm] = Facter::Core::Execution.exec('rpm -qa | grep gnome') != ''

    grub = {}
    grubpwd = Facter::Core::Execution.exec('grep "^GRUB2_PASSWORD" /boot/grub2/grub.cfg')
    grub[:grub_passwd] = if grubpwd.empty?
                           false
                         else
                           true
                         end
    uid = File.stat('/boot/grub2/grub.cfg').uid
    gid = File.stat('/boot/grub2/grub.cfg').gid
    mode = File.stat('/boot/grub2/grub.cfg').mode
    grub['grub.cfg'] = {
      uid: uid,
      gid: gid,
      mode: mode,
    }

    uid = File.stat('/boot/grub2/user.cfg').uid
    gid = File.stat('/boot/grub2/user.cfg').gid
    mode = File.stat('/boot/grub2/user.cfg').mode
    grub['user.cfg'] = {
      uid: uid,
      gid: gid,
      mode: mode,
    }
    security_baseline[:grub] = grub

    tcp_wrapper = {}
    tcp_wrapper['host_allow'] = File.exist?('/etc/hosts.allow')
    tcp_wrapper['host_deny'] = File.exist?('/etc/hosts.deny')
    security_baseline[:tcp_wrapper] = tcp_wrapper

    coredumps = {}
    if security_baseline['sysctl'].key?('fs_dumpable')
      fsdumpable = security_baseline['sysctl']['fs_dumpable']
    else
      undef fsdumpable
    end
    coredumps['limits'] = Facter::Core::Execution.exec('grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*')
    coredumps['status'] = if coredumps['limits'].empty? || (fsdumpable && (security_baseline['sysctl']['fs_dumpable'] != 0))
                            false
                          else
                            true
                          end

    security_baseline[:coredumps] = coredumps

    security_baseline
  end
end
