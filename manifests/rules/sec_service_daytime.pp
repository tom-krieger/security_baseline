# @summary 
#    Ensure daytime services are not enabled (Scored)
#
# daytime is a network service that responds with the server's current date and time. This service 
# is intended for debugging and testing purposes. It is recommended that this service be disabled.
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
#   class security_baseline::rules::sec_service_daytime {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_service_daytime (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service { 'daytime-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'daytime-stream':
      ensure => stopped,
      enable => false,
    }

  } else {

    if($::srv_daytime == true) {

      echo { 'daytime-service':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }

    }
  }
}
