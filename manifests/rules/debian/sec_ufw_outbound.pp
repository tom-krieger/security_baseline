# @summary 
#    Ensure outbound connections are configured (Not Scored)
#
# Configure the firewall rules for new outbound connections.
#
# Rationale:
# If rules are not in place for new outbound connections all packets will be dropped by the 
# default policy preventing network usage.
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
# @param firewall_rules
#    Rules for outbound connections
#
# @example
#   class security_baseline::rules::debian::sec_ufw_outbound {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::debian::sec_ufw_outbound (
  Boolean $enforce     = true,
  String $message      = '',
  String $log_level    = '',
  Hash $firewall_rules = {},
) {
  if ($enforce) {
    $firewall_rules.each |$title, $data| {

      if ($data['queue'] == 'in') {
        $cmd = "ufw ${data['action']} ${data['queue']} ${data['port']}/${data['proto']}"
        $check = "test -z \"$(ufw status verbose | grep -E -i '^${data['port']}/${data['proto']}.*ALLOW ${data['queue']}')\""
      } elsif ($data['queue'] == 'out') {
        $cmd = "ufw ${data['action']} ${data['queue']} to ${data['to']} port ${data['port']}/${data['proto']}"
        $check = "test -z \"$(ufw status verbose | grep -E -i '^${data['port']}.*ALLOW ${data['queue']}')\""
      } else {
        fail("unknow ufw queue ${data['queue']}")
      }
      exec { $title:
        command => $cmd,
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        onlyif  => $check,
      }
    }
  }
}
