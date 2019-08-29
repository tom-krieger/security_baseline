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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_network_packet_redirect {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_packet_redirect (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv4.conf.all.send_redirects':
        value => 0;
      'net.ipv4.conf.default.send_redirects':
        value => 0;
    }

  } else {

    if(has_key($::network_parameters, 'net.ipv4.conf.all.send_redirects' )) {
      $fact = $::network_parameters['net.ipv4.conf.all.send_redirects']
    } else {
      $fact = ''
    }
    if(has_key($::network_parameters, 'net.ipv4.conf.default.send_redirects')) {
      $fact_default = $::network_parameters['net.ipv4.conf.default.send_redirects']
    } else {
      $fact_default = ''
    }
    if(($fact != '0') or ($fact_default != '0')) {
      notify { 'net.ipv4.conf.all.send_redirects':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
