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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::sec_network_ipv6_disable {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_ipv6_disable (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv6.conf.all.disable_ipv6':
        value => 1;
      'net.ipv6.conf.default.disable_ipv6':
        value => 1;
    }

  } else {

    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv6.conf.all.disable_ipv6' )) {
      $fact = $facts['security_baseline']['sysctl']['net.ipv6.conf.all.disable_ipv6']
    } else {
      $fact = ''
    }
    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv6.conf.default.disable_ipv6')) {
      $fact_default = $facts['security_baseline']['sysctl']['net.ipv6.conf.default.disable_ipv6']
    } else {
      $fact_default = ''
    }
    if(($fact != '1') or ($fact_default != '1')) {
      echo { 'net.ipv6.conf.all.disable_ipv6':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
