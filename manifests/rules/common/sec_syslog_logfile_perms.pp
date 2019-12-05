# @summary 
#    Ensure permissions on all logfiles are configured (Scored)
#
# Log files stored in /var/log/ contain logged information from many services on the system, 
# or on log hosts others as well.
#
# Rationale:
# It is important to ensure that log files have the correct permissions to ensure that sensitive 
# data is archived and protected.
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
#   class security_baseline::rules::common::sec_syslog_logfile_perms {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::common::sec_syslog_logfile_perms (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if($enforce) {
    file { '/var/log':
      ensure  => directory,
      recurse => true,
      mode    => 'g-wx,o-rwx',     #lint:ignore:no_symbolic_file_modes
      ignore  => ['puppetlabs', 'puppet'],
    }
  } else {
    if($facts['security_baseline']['syslog']['log_status'] != 'ok') {
      echo { 'syslog-log-file-perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
