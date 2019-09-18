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
#   class security_baseline::rules::sec_network_log_suspicious_packets {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_log_suspicious_packets (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv4.conf.all.log_martians':
        value => 1;
      'net.ipv4.conf.default.log_martians':
        value => 1;
    }

  } else {

    if(has_key($::network_parameters, 'net.ipv4.conf.all.log_martians' )) {
      $fact = $::network_parameters['net.ipv4.conf.all.log_martians']
    } else {
      $fact = ''
    }
    if(has_key($::network_parameters, 'net.ipv4.conf.default.log_martians')) {
      $fact_default = $::network_parameters['net.ipv4.conf.default.log_martians']
    } else {
      $fact_default = ''
    }
    if(($fact != '1') or ($fact_default != '1')) {
      echo { 'net.ipv4.conf.all.log_martians':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
