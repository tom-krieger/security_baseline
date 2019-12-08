# @summary 
#    Ensure ICMP redirects are not accepted (Scored)
#
# ICMP redirect messages are packets that convey routing information and tell your host 
# (acting as a router) to send packets via an alternate path. It is a way of allowing an 
# outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects 
# to 0, the system will not accept any ICMP redirect messages, and therefore, won't allow outsiders to update 
# the system's routing tables.
#
# Rationale:
# Attackers could use bogus ICMP redirect messages to maliciously alter the system routing tables and get 
# them to send packets to incorrect networks and allow your system packets to be captured.
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
#   class security_baseline::rules::common::sec_network_ipv6_redirect {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_network_ipv6_redirects (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv6.conf.all.accept_redirects':
        value => 0;
    }
    sysctl {
      'net.ipv6.conf.default.accept_redirects':
        value => 0;
    }

  } else {

    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv6.conf.all.accept_redirects' )) {
      $fact = $facts['security_baseline']['sysctl']['net.ipv6.conf.all.accept_redirects']
    } else {
      $fact = ''
    }
    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv6.conf.default.accept_redirects')) {
      $fact_default = $facts['security_baseline']['sysctl']['net.ipv6.conf.default.accept_redirects']
    } else {
      $fact_default = ''
    }
    if(($fact != '0') or ($fact_default != '0')) {
      echo { 'net.ipv6.conf.all.accept_redirects':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
