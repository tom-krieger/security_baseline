# @summary 
#    Ensure secure ICMP redirects are not accepted (Scored)
#
# Secure ICMP redirects are the same as ICMP redirects, except they come from gateways listed 
# on the default gateway list. It is assumed that these gateways are known to your system, and 
# that they are likely to be secure.
# 
# Rationale:
# It is still possible for even known gateways to be compromised. Setting 
# net.ipv4.conf.all.secure_redirects to 0 protects the system from routing table updates by 
# possibly compromised known gateways.
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
#   class security_baseline::rules::common::sec_network_secure_icmp_redirect {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_network_secure_icmp_redirect (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv4.conf.all.secure_redirects':
        value => 0;
      'net.ipv4.conf.default.secure_redirects':
        value => 0;
    }

  } else {

    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv4.conf.all.secure_redirects' )) {
      $fact = $facts['security_baseline']['sysctl']['net.ipv4.conf.all.secure_redirects']
    } else {
      $fact = ''
    }
    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv4.conf.default.secure_redirects')) {
      $fact_default = $facts['security_baseline']['sysctl']['net.ipv4.conf.default.secure_redirects']
    } else {
      $fact_default = ''
    }
    if(($fact != '0') or ($fact_default != '0')) {
      echo { 'net.ipv4.conf.all.secure_redirects':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
