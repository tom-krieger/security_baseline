# @summary 
#    Ensure ntp is configured (Scored)
#
# ntp is a daemon which implements the Network Time Protocol (NTP). It is designed to synchronize system 
# clocks across a variety of systems and use a source that is highly accurate. More information on NTP can 
# be found at http://www.ntp.org. ntp can be configured to be a client and/or a server.
# This recommendation only applies if ntp is in use on the system.
#
# Rationale:
# If ntp is in use on the system proper configuration is vital to ensuring time synchronization is working 
# properly.
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
# @param ntp_restrict
#    NTP daemon restrictions depending on the daemon used
#
# @param ntp_driftfile
#    Drift file for ntp daemon
#
# @param ntp_statsdir
#    NTP stats dir
#
# @param ntp_disable_monitor
#    Disables the monitoring facility in NTP
#
# @param ntp_burst
#    Specifies whether to enable the iburst option for every NTP peer.
#
# @example
#   class security_baseline::rules::common::sec_ntp_daemon_ntp {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       ntp_daemon => 'ntp',  
#       ntp_servers => ['server1', 'server2'],
#       }
#   }
#
# @api private
class security_baseline::rules::common::sec_ntp_daemon_ntp (
  Boolean $enforce                        = true,
  String $message                         = '',
  String $log_level                       = '',
  Integer $level                          = 1,
  Boolean $scored                         = true,
  String $logfile                         = '',
  Array $ntp_servers                      = [],
  Array $ntp_restrict                     = [],
  String $ntp_driftfile                   = '',
  String $ntp_statsdir                    = '',
  Boolean $ntp_disable_monitor            = true,
  Boolean $ntp_burst                      = false,
) {
  if($enforce) {
    if(empty($ntp_servers)) {
      fail("Can't configure ntp daemon without ntp servers")
    }
    $ntp_default = {
      servers         => $ntp_servers,
      restrict        => $ntp_restrict,
      statsdir        => $ntp_statsdir,
      disable_monitor => $ntp_disable_monitor,
      iburst_enable   => $ntp_burst,
    }

    if($ntp_driftfile == '') {
      $ntp_drift = {}
    } else {
      $ntp_drift = {
        driftfile       => $ntp_driftfile,
      }
    }

    $ntp_data = $ntp_default + $ntp_drift

    class { '::ntp':
      * => $ntp_data,
    }

    file { '/etc/sysconfig/ntpd':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => 'OPTIONS="-u ntp:ntp"',
    }
  } else {
    if ($facts['security_baseline']['ntp']['ntp_status'] == false) {
      echo { 'ntp-daemon':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
