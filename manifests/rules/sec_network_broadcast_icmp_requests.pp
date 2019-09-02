# @summary 
#    Ensure broadcast ICMP requests are ignored (Scored)
#
# Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo 
# and timestamp requests to broadcast and multicast addresses.
#
# Rationale:
# Accepting ICMP echo and timestamp requests with broadcast or multicast destinations for your 
# network could be used to trick your host into starting (or participating) in a Smurf attack. A Smurf 
# attack relies on an attacker sending large amounts of ICMP broadcast messages with a spoofed source 
# address. All hosts receiving this message and responding would send echo-reply messages back to the 
# spoofed address, which is probably not routable. If many hosts respond to the packets, the amount of 
# traffic on the network could be significantly multiplied.
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
#   class security_baseline::rules::sec_network_broadcast_icmp_requests{
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_network_broadcast_icmp_requests (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv4.icmp_echo_ignore_broadcasts':
        value => 1
    }

  } else {

    if(has_key($::network_parameters, 'net.ipv4.icmp_echo_ignore_broadcasts')) {
      $fact = $::network_parameters['net.ipv4.icmp_echo_ignore_broadcasts']
    } else {
      $fact = ''
    }
    if($fact != '1') {
      echo { 'net.ipv4.icmp_echo_ignore_broadcasts':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }
    }
  }
}
