# @summary 
#    Ensure discard services are not enabled (Scored)
#
# discardis a network service that simply discards all data it receives. This service is 
# intended for debugging and testing purposes. It is recommended that this service be 
# disabled.
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
#   class security_baseline::rules::redhat::sec_service_discard {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_service_discard (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service { 'discard-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'discard-stream':
      ensure => stopped,
      enable => false,
    }

  } else {

    if($facts['security_baseline']['xinetd_services']['srv_discard'] == true) {

      echo { 'discard-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
