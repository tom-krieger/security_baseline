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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::sles::sec_service_time {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_service_time (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    Service { 'time':
      ensure => stopped,
      enable => false,
    }

    Service { 'time-udp':
      ensure => stopped,
      enable => false,
    }

  } else {

    if($facts['security_baseline']['xinetd_services']['srv_time'] == true) {

      echo { 'time-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
