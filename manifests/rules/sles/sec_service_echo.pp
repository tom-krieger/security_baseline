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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::sles::sec_service_echo {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_service_echo (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    ensure_resource('service', ['echo', 'echo-udp'], {
      ensure => stopped,
      enable => false,
    })

  } else {

    if($facts['security_baseline']['xinetd_services']['srv_echo'] == true) {

      echo { 'echo-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
