# @summary 
#    Ensure audit logs are not automatically deleted (Scored)
#
# The max_log_file_action setting determines how to handle the audit log file reaching the max file 
# size. A value of keep_logs will rotate the logs but never delete old logs.
#
# Rationale:
# In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing 
# the audit history.
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
# @param max_log_file
#    Maximal log file size, defaults to 26 MB
#
# @example
#   class { 'security_baseline::rules::redhat::sec_auditd_max_logfile_action':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#             max_log_file_action => 'keep_logs',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_auditd_max_logfile_action (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  String $max_log_file_action = 'keep_logs',
) {
  if($enforce) {
    file_line { 'auditd_max_log_file_action':
      line  => "max_log_file_action = ${$max_log_file_action}",
      path  => '/etc/audit/auditd.conf',
      match => '^$max_log_file_action',
    }
  } else {
    if($facts['security_baseline']['auditd']['max_log_file_action'] == 'none') {
      echo { 'auditd-max-log-action':
        message  => 'Auditd setting for max_log_file_action is not correct.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
