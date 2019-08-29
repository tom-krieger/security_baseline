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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_network_secure_icmp_redirect {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_secure_icmp_redirect (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv4.conf.all.secure_redirects':
        value => 0;
      'net.ipv4.conf.default.secure_redirects':
        value => 0;
    }

  } else {

    if(has_key($::network_parameters, 'net.ipv4.conf.all.secure_redirects' )) {
      $fact = $::network_parameters['net.ipv4.conf.all.secure_redirects']
    } else {
      $fact = ''
    }
    if(has_key($::network_parameters, 'net.ipv4.conf.default.secure_redirects')) {
      $fact_default = $::network_parameters['net.ipv4.conf.default.secure_redirects']
    } else {
      $fact_default = ''
    }
    if(($fact != '0') or ($fact_default != '0')) {
      notify { 'net.ipv4.conf.all.secure_redirects':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
