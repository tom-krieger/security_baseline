# @summary 
#    Ensure CUPS is not enabled (Scored)
#
# The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. 
# A system running CUPS can also accept print jobs from remote systems and print them to local printers. 
# It also provides a web based remote administration capability.
#
# Rationale:
# If the system does not need to print jobs or accept print jobs from other systems, it is recommended 
# that CUPS be disabled to reduce the potential attack surface.
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
#   class security_baseline::rules::sec_cups {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_cups (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    service {'cups':
      ensure => 'stopped',
      enable => false
      }

  } else {

    if($facts['security_baseline']['services_enabled']['srv_cups'] == 'enabled') {
      echo { 'cups':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
