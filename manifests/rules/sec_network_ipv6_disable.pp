# @summary 
#    Ensure IPv6 is disabled (Not Scored)
#
# Although IPv6 has many advantages over IPv4, few organizations have implemented IPv6.
#
# Rationale:
# If IPv6 is not to be used, it is recommended that it be disabled to reduce the attack surface of the system.
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
#   class security_baseline::rules::sec_network_ipv6_disable {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_ipv6_disable (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv6.conf.all.disable_ipv6':
        value => 1;
      'net.ipv6.conf.default.disable_ipv6':
        value => 1;
    }

  } else {

    if(has_key($::network_parameters, 'net.ipv6.conf.all.disable_ipv6' )) {
      $fact = $::network_parameters['net.ipv6.conf.all.disable_ipv6']
    } else {
      $fact = ''
    }
    if(has_key($::network_parameters, 'net.ipv6.conf.default.disable_ipv6')) {
      $fact_default = $::network_parameters['net.ipv6.conf.default.disable_ipv6']
    } else {
      $fact_default = ''
    }
    if(($fact != '1') or ($fact_default != '1')) {
      echo { 'net.ipv6.conf.all.disable_ipv6':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }
    }
  }
}
