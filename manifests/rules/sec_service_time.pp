# @summary 
#    Ensure time services are not enabled (Scored)
#
# timeis a network service that responds with the server's current date and time as a 32 bit 
# integer. This service is intended for debugging and testing purposes. It is recommended 
# that this service be disabled.
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
#   class security_baseline::rules::sec_service_time {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_service_time (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service { 'time-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'time-stream':
      ensure => stopped,
      enable => false,
    }

  } else {

    if($::srv_time == true) {

      echo { 'time-service':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }

    }
  }
}
