# @summary 
#    Ensure sudo log file exists (Scored)
#
# sudo can use a custom log file
#
# Rationale:
# A sudo log file simplifies auditing of sudo commands
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::common::sec_sudo_logfile {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sudo_logfile (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'sudo logfile':
      path               => '/etc/sudoers',
      match              => 'Defaults.*logfile\s*=',
      append_on_no_match => true,
      line               => 'Defaults logfile="/var/log/sudo.log"',
    }
  } else {
    if ($facts['security_baseline']['sudo']['logfile'] == 'none') {
      echo { 'sudo-logfile':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
