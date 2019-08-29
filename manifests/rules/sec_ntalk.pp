# @summary 
#    Ensure talk server is not enabled (Scored)
#
# The talk software makes it possible for users to send and receive messages across systems through a 
# terminal session. The talk client (allows initiate of talk sessions) is installed by default.
#
# Rationale:
# The software presents a security risk as it uses unencrypted protocols for communication.
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
#   class security_baseline::rules::sec_ntalk {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_ntalk (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'ntalk':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($::srv_ntalk == 'enabled') {
      notify { 'ntalk':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
