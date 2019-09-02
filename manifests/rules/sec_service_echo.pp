# @summary 
#    Ensure echo services are not enabled (Scored)
#
# echo is a network service that responds to clients with the data sent to it by the client. 
# This service is intended for debugging and testing purposes. It is recommended that this 
# service be disabled.
#
# Rationale:
# Disabling this service will reduce the remote attack surface of the system.
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
#   class security_baseline::rules::sec_service_echo {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_service_echo (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service { 'echo-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'echo-stream':
      ensure => stopped,
      enable => false,
    }

  } else {

    if($::srv_echo == true) {

      echo { 'echo-service':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }

    }
  }
}
