# @summary 
#    Ensure changes to system administration scope (sudoers) is collected (Scored)
#
# Monitor scope changes for system administrations. If the system has been properly configured 
# to force system administrators to log in as themselves first and then use the sudo command to 
# execute privileged commands, it is possible to monitor changes in scope. The file /etc/sudoers 
# will be written to when the file or its attributes have changed. The audit records will be tagged 
# with the identifier "scope."
# 
# Rationale:
# Changes in the /etc/sudoers file can indicate that an unauthorized change has been made to scope 
# of system administrator activity.
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
#   class { 'security_baseline::rules::common::sec_auditd_scope':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_scope (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'watch scope rule 1':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /etc/sudoers -p wa -k scope',
      notify => Exec['reload auditd rules'],
    }
    file_line { 'watch scope rule 2':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /etc/sudoers.d/ -p wa -k scope',
      notify => Exec['reload auditd rules'],
    }
  } else {
    if($facts['security_baseline']['auditd']['scope'] == false) {
      echo { 'auditd-scope':
        message  => 'Auditd has no rule to collect changes to system administration scope (sudoers).',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
