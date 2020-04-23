# @summary 
#    Ensure packet redirect sending is disabled (Scored)
#
# ICMP Redirects are used to send routing information to other hosts. As a host itself does not act 
# as a router (in a host only configuration), there is no need to send redirects.
#
# Rationale:
# An attacker could use a compromised host to send invalid ICMP redirects to other router devices in 
# an attempt to corrupt routing and have users access a system set up by the attacker as opposed to 
# a valid system.
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
#   class security_baseline::rules::common::sec_network_packet_redirect {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_network_packet_redirect (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    Sysctl {
      'net.ipv4.conf.all.send_redirects':
        value => 0;
    }
    Sysctl {
      'net.ipv4.conf.default.send_redirects':
        value => 0;
    }

  } else {

    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv4.conf.all.send_redirects' )) {
      $fact = $facts['security_baseline']['sysctl']['net.ipv4.conf.all.send_redirects']
    } else {
      $fact = ''
    }
    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv4.conf.default.send_redirects')) {
      $fact_default = $facts['security_baseline']['sysctl']['net.ipv4.conf.default.send_redirects']
    } else {
      $fact_default = ''
    }
    if(($fact != '0') or ($fact_default != '0')) {
      echo { 'net.ipv4.conf.all.send_redirects':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
