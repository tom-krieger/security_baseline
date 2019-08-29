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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_service_discard {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_service_discard (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
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

    if($::srv_discard == true) {

      notify { 'discard-service':
        message  => $message,
        loglevel => $loglevel,
      }

    }
  }
}
