# @summary 
#    Ensure talk server is not enabled (Scored)
#
# The talk software makes it possible for users to send and receive messages across systems through 
# a terminal session. The talk client (allows initiate of talk sessions) is installed by default.
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
#   class security_baseline::rules::redhat::sec_service_talk {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_service_talk (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

    Service { 'talk':
      ensure => stopped,
      enable => false,
    }

  } else {

    if($facts['security_baseline']['xinetd_services']['srv_talk'] == true) {

      echo { 'talk-service':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
