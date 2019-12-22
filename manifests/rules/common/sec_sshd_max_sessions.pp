# @summary 
#    Ensure SSH MaxSessions is set to 4 or less (Scored)
#
# The MaxSessions parameter specifies the maximum number of open sessions permitted from a given connection.
#
# Rationale:
# To protect a system from denial of service due to a large number of concurrent sessions, use the rate 
# limiting function of MaxSessions to protect availability of sshd logins and prevent overwhelming the daemon.
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
#   class security_baseline::rules::common::sec_sshd_max_sessions {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_max_sessions (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'sshd-max-sessions':
      ensure             => present,
      path               => '/etc/ssh/sshd_config',
      line               => 'maxsessions 4',
      match              => '^maxsessions.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  } else {
    if($facts['security_baseline']['sshd']['maxsessions'] != '4') {
        echo { 'sshd-max-sessions':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
  }
}
