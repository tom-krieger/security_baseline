# @summary 
#    Ensure system administrator actions (sudolog) are collected (Scored)
#
# Monitor the sudo log file. If the system has been properly configured to disable the use 
# of the su command and force all administrators to have to log in first and then use sudo 
# to execute privileged commands, then all administrator commands will be logged to /var/log/sudo.log. 
# Any time a command is executed, an audit event will be triggered as the /var/log/sudo.log file will 
# be opened for write and the executed administration command will be written to the log.
#
# Rationale:
# Changes in /var/log/sudo.log indicate that an administrator has executed a command or the log file 
# itself has been tampered with. Administrators will want to correlate the events written to the audit 
# trail with the records written to /var/log/sudo.log to verify if unauthorized commands have been executed.
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
#   class { 'security_baseline::rules::redhat::sec_auditd_actions':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_auditd_actions (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    file_line { 'watch admin actions rule 1':
      ensure => present,
      path   => $security_baseline::auditd_rules_file,
      line   => '-w /var/log/sudo.log -p wa -k actions',
      notify => Exec['reload auditd rules'],
    }
  } else {
    if($facts['security_baseline']['auditd']['actions'] == false) {
      echo { 'auditd-actions':
        message  => 'Auditd has no rule to collect system administrator actions (sudolog).',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
