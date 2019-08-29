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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_rsyncd {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_rsyncd (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'rsyncd':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($::srv_rsyncd == 'enabled') {
      notify { 'rsyncd':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
