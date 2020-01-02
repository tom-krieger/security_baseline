# @summary 
#    Ensure talk server is not enabled (Scored)
#
# The rsyncd service can be used to synchronize files between systems over network links.
#
# Rationale:
# The rsyncd service presents a security risk as it uses unencrypted protocols for communication.
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
#   class security_baseline::rules::redhat::sec_rsyncd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_rsyncd (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    if($facts['operatingsystemmajrelease'] > '6') {
      service {'rsyncd':
        ensure => 'stopped',
        enable => false,
      }
    } else {
        service {'rsync':
        ensure => 'stopped',
        enable => false,
      }
    }
  } else {
    if($facts['operatingsystemmajrelease'] > '6') {
      $status = $facts['security_baseline']['services_enabled']['srv_rsyncd']
    } else {
      $status = $facts['security_baseline']['xinetd_services']['srv_rsync']
    }

    if(($status == 'enabled') or ($status == true)) {
      echo { 'rsyncd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
