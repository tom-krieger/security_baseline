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
#   class security_baseline::rules::sles::sec_rsyncd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_rsyncd (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'rsyncd':
      ensure => 'stopped',
      enable => false,
    }

  } else {

    if($facts['security_baseline']['services_enabled']['srv_rsyncd'] == 'enabled') {
      echo { 'rsyncd':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
