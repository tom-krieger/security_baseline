# @summary 
#    Ensure source routed packets are not accepted (Scored)
#
# In networking, source routing allows a sender to partially or fully specify the route packets 
# take through a network. In contrast, non-source routed packets travel a path determined by 
# routers in the network. In some cases, systems may not be routable or reachable from some 
# locations (e.g. private addresses vs. Internet routable), and so source routed packets would 
# need to be used.
# 
# Rationale:
# Setting net.ipv4.conf.all.accept_source_route and net.ipv4.conf.default.accept_source_route to 
# 0 disables the system from accepting source routed packets. Assume this system was capable of 
# routing packets to Internet routable addresses on one interface and private addresses on another 
# interface. Assume that the private addresses were not routable to the Internet routable addresses 
# and vice versa. Under normal routing circumstances, an attacker from the Internet routable 
# addresses could not use the system as a way to reach the private address systems. If, however, 
# source routed packets were allowed, they could be used to gain access to the private address systems 
# as the route could be specified, rather than rely on routing protocols that did not allow this routing.
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
#   class security_baseline::rules::common::sec_network_source_route {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_network_source_route (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    sysctl {
      'net.ipv4.conf.all.accept_source_route':
        value => 0;
    }
    sysctl {
      'net.ipv4.conf.default.accept_source_route':
        value => 0;
    }

  } else {

    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv4.conf.all.accept_source_route' )) {
      $fact = $facts['security_baseline']['sysctl']['net.ipv4.conf.all.accept_source_route']
    } else {
      $fact = ''
    }
    if(has_key($facts['security_baseline']['sysctl'], 'net.ipv4.conf.default.accept_source_route')) {
      $fact_default = $facts['security_baseline']['sysctl']['net.ipv4.conf.default.accept_source_route']
    } else {
      $fact_default = ''
    }
    if(($fact != '0') or ($fact_default != '0')) {
      echo { 'net.ipv4.conf.all.accept_source_route':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
