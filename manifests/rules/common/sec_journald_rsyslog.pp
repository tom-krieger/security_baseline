# @summary 
#    Ensure journald is configured to send logs to rsyslog (Scored)
#
# Data from journald may be stored in volatile memory or persisted locally on the server. Utilities exist 
# to accept remote export of journald logs, however, use of the rsyslog service provides a consistent 
# means of log collection and export.
#
# Rationale:
# Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root 
# access on the local system, they could tamper with or remove log data that is stored on the local system.
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
#   class security_baseline::rules::common::sec_journald_rsyslog {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_journald_rsyslog (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'enable syslog forwarding':
      path  => '/etc/systemd/journald.conf',
      match => 'ForwardToSyslog=',
      line  => 'ForwardToSyslog=yes',
    }
  } else {
    if (
      ($facts['security_baseline']['journald']['forward_to_syslog'] == 'none') or
      ($facts['security_baseline']['journald']['forward_to_syslog'] == 'no')
    ) {
      echo { 'journald-forward-rsyslog':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
