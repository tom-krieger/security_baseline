# @summary 
#    Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
#
# Monitor SELinux mandatory access controls. The parameters below monitor any write access (potential additional, 
# deletion or modification of files in the directory) or attribute changes to the /etc/selinux or directory.
#
# Rationale:
# Changes to files in these directories could indicate that an unauthorized user is attempting to modify access 
# controls and change security contexts, leading to a compromise of the system.
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
#   class { 'security_baseline::rules::common::sec_auditd_mac_policy':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_mac_policy (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'mac policy rule 1':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /etc/selinux/ -p wa -k MAC-policy',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'mac policy rule 2':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /usr/share/selinux/ -p wa -k MAC-policy',
      notify => Exec['reload auditd rules'],
    }
  } else {
    if($facts['security_baseline']['auditd']['mac-policy'] == false) {
      echo { 'auditd-mac-policy':
        message  => 'Auditd has no rule to collect events changing mandatory access controls.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
