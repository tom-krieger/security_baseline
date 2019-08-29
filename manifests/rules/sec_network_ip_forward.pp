# @summary 
#    Ensure IP forwarding is disabled (Scored)
#
# The net.ipv4.ip_forward flag is used to tell the system whether it can forward packets or not.
#
# Rationale:
# Setting the flag to 0 ensures that a system with multiple interfaces (for example, a hard proxy), 
# will never be able to forward packets, and therefore, never serve as a router.
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
#   class security_baseline::rules::sec_network_ip_forward {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_ip_forward (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv4.ip_forward':
        value => 0
    }

  } else {

    if(has_key($::network_parameters, 'net.ipv4.ip_forward')) {
      $fact = $::network_parameters['net.ipv4.ip_forward']
    } else {
      $fact = ''
    }
    if($fact != '0') {
      notify { 'net.ipv4.ip_forward':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
