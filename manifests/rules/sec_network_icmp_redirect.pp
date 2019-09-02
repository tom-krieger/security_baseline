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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_network_icmp_redirect {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_icmp_redirect (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv4.conf.all.accept_redirects':
        value => 0;
      'net.ipv4.conf.default.accept_redirects':
        value => 0;
    }

  } else {

    if(has_key($::network_parameters, 'net.ipv4.conf.all.accept_redirects' )) {
      $fact = $::network_parameters['net.ipv4.conf.all.accept_redirects']
    } else {
      $fact = ''
    }
    if(has_key($::network_parameters, 'net.ipv4.conf.default.accept_redirects')) {
      $fact_default = $::network_parameters['net.ipv4.conf.default.accept_redirects']
    } else {
      $fact_default = ''
    }
    if(($fact != '0') or ($fact_default != '0')) {
      echo { 'net.ipv4.conf.all.accept_redirects':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }
    }
  }
}
