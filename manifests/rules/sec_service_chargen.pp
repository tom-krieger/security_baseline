# @summary 
#    Ensure chargen services are not enabled (Scored)
#
# chargen is a network service that responds with 0 to 512 ASCII characters for each connection 
# it receives. This service is intended for debugging and testing purposes. It is recommended 
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
#   class security_baseline::rules::sec_service_chargen {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_service_chargen (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service { 'chargen-dgram':
      ensure => stopped,
      enable => false,
    }

    service { 'chargen-stream':
      ensure => stopped,
      enable => false,
    }

  } else {

    if($::srv_chargen == true) {

      echo { 'chargen-service':
        message  => $message,
        loglevel => $loglevel,
      }

    }
  }
}
