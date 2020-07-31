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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::common::sec_ntalk {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_ntalk (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    ensure_resource('service', ['ntalk'], {
      ensure => 'stopped',
      enable => false
    })

  } else {

    if($facts['security_baseline']['services_enabled']['srv_ntalk'] == 'enabled') {
      echo { 'ntalk':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
