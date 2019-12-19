# @summary 
#    Ensure events that modify the system's network environment are collected (Scored)
#
# Record changes to network environment files or system calls. The below parameters monitor the sethostname 
# (set the systems host name) or setdomainname (set the systems domainname) system calls, and write an audit 
# event on system call exit. The other parameters monitor the /etc/issue and /etc/issue.net files (messages 
# displayed pre- login), /etc/hosts (file containing host names and associated IP addresses), 
# /etc/sysconfig/network file and /etc/sysconfig/network-scripts/ directory (containing network interface 
# scripts and configurations).
#
# Rationale:
# Monitoring sethostname and setdomainname will identify potential unauthorized changes to host and domainname 
# of a system. The changing of these names could potentially break security parameters that are set based on those 
# names. The /etc/hosts file is monitored for changes in the file that can indicate an unauthorized intruder is 
# trying to change machine associations with IP addresses and trick users and processes into connecting to 
# unintended machines. Monitoring /etc/issue and /etc/issue.net is important, as intruders could put disinformation 
# into those files and trick users into providing information to the intruder. Monitoring /etc/sysconfig/network 
# and /etc/sysconfig/network-scripts/ is important as it can show if network interfaces or scripts are being modified 
# in a way that can lead to the machine becoming unavailable or compromised. All audit records will be tagged with 
# the identifier "system-locale."
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param message
#    Message to print into the log
#
# @param log_level
#    Loglevel for the message
#
# @example
#   class { 'security_baseline::rules::debian::sec_auditd_system_locale':   
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::debian::sec_auditd_system_locale (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'watch network environment rule 1':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch network environment rule 2':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /etc/issue -p wa -k system-locale',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch network environment rule 3':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /etc/issue.net -p wa -k system-locale',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch network environment rule 4':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /etc/hosts -p wa -k system-locale',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch network environment rule 5':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /etc/network -p wa -k system-locale',
      notify => Exec['reload auditd rules'],
    }
    if($facts['architecture'] == 'x86_64') {
      file_line { 'watch network environment rule 7':
        ensure => present,
        path   => $security_baseline::auditd_rules_file,
        line   => '-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale',
        notify => Exec['reload auditd rules'],
      }
    }
  } else {
    if($facts['security_baseline']['auditd']['system-locale'] == false) {
      echo { 'auditd-locale':
        message  => 'Auditd has no rule to collect events modifying network environment.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
