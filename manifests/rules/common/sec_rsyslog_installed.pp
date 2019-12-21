# @summary 
#    Ensure rsyslog or syslog-ng is installed (Scored)
#
# The rsyslog and syslog-ng software are recommended replacements to the original syslogd daemon which 
# provide improvements over syslogd , such as connection-oriented (i.e. TCP) transmission of logs, the 
# option to log to database formats, and the encryption of log data en route to a central logging server.
#
# Rationale:
# The security enhancements of rsyslog and syslog-ng such as connection-oriented (i.e. TCP) transmission of 
# logs, the option to log to database formats, and the encryption of log data en route to a central logging 
# server) justify installing and configuring the package.
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
#   class security_baseline::rules::common::sec_rsyslog_installed {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::common::sec_rsyslog_installed (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if($enforce) {
    if(!defined(Package['rsyslog'])) {
      package { 'rsyslog':
        ensure => installed,
      }
    }
  } else {
    if($facts['security_baseline']['packages_installed']['rsyslog'] == false) {
      echo { 'rsyslog-installed':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
