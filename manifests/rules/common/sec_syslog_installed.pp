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
# @param syslog_daemon
#    Syslog daemon to use, can be rsyslog or syslog-ng.
#
# @example
#   class security_baseline::rules::common::sec_syslog_installed {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::common::sec_syslog_installed (
  Boolean $enforce                            = true,
  String $message                             = '',
  String $log_level                           = '',
  Enum['rsyslog', 'syslog-ng'] $syslog_daemon = 'rsyslog',
) {
  if($enforce) {
    if($syslog_daemon == 'rsyslog') {
      if(!defined(Package['rsyslog'])) {

        ensure_packages(['rsyslog'], {
          ensure => installed,
        })

        ensure_packages(['syslog-ng'], {
          ensure => absent,
        })

      }
    } elsif ($syslog_daemon == 'syslog-ng') {
      if(!defined(Package['syslog-ng'])) {
        ensure_packages(['rsyslog'], {
          ensure => absent,
        })

        ensure_packages(['syslog-ng'], {
          ensure => installed,
        })
      }
    } else {
      fail("Unknown syslog daemon: ${syslog_daemon}")
    }
  } else {
    if($facts['security_baseline']['syslog']['syslog_installed'] != true) {
      echo { 'syslog-installed':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
