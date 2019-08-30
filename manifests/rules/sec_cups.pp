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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_cups {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_cups (
  Boolean $enforce = true, # TODO: Alignment
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    service {'cups':
      ensure => 'stopped',
      enable => false
      } # TODO: Alignment

  } else {

    if($::srv_cups == 'enabled') {
      notify { 'cups':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
