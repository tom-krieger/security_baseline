# @summary 
#    Ensure chrony is configured (Scored)
#
# chrony is a daemon which implements the Network Time Protocol (NTP) is designed to synchronize system 
# clocks across a variety of systems and use a source that is highly accurate. More information on chrony 
# can be found at http://chrony.tuxfamily.org/. chrony can be configured to be a client and/or a server.
#
# Rationale:
# If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working 
# properly.
# This recommendation only applies if chrony is in use on the system.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param log_level
#    The loglevel for the above message
#
# @param level
#    Profile level
#
# @param scored
#    Indicates if a rule is scored or not
#
# @param ntp_server
#    NTP servers to use, depends on the daemon used
#
# @example
#   class ecurity_baseline::rules::common::sec_ntp_daemon_chrony {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       ntp_servers => ['server1', 'server2'],
#     }
#   }
#
# @api private
class security_baseline::rules::common::sec_ntp_daemon_chrony (
  Boolean $enforce                        = true,
  String $message                         = '',
  String $log_level                       = '',
  Integer $level                          = 1,
  Boolean $scored                         = true,
  String $logfile                         = '',
  Array $ntp_servers                      = [],
) {
  if($enforce) {
    class { 'chrony':
      servers => $ntp_servers,
    }
  } else {
    if ($facts['security_baseline']['ntp']['chrony_status'] == false) {
      echo { 'chrony-daemon':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
