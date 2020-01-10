# @summary 
#    Ensure firewall rules exist for all open ports (Not Scored)
#
# Any ports that have been opened on non-loopback addresses need firewall rules to govern traffic.
#
# Rationale:
# Without a firewall rule configured for open ports default firewall policy will drop all packets to these ports.
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
#    Rules for inbound connections
#
# @example
#   class security_baseline::rules::debian::sec_ufw_open_ports {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::debian::sec_ufw_open_ports (
  Boolean $enforce     = true,
  String $message      = '',
  String $log_level    = '',
  Hash $firewall_rules = {},
) {
  if ($enforce) {
    $firewall_rules.each |$title, $data| {

      if ($data['queue'] == 'in') {
        if(has_key($data, 'from')) {
          $from = "from ${data['from']} "
        } else {
          $from = ''
        }
        if (has_key($data, 'to')) {
          $to = "to ${data['to']} "
        } else {
          $to = ''
        }
        $cmd = "ufw ${data['action']} proto ${data['proto']} ${from}${to}port ${data['port']}"
        $check = "test -z \"$(ufw status verbose | grep -E -i '^${data['port']}/${data['proto']}.*ALLOW ${data['queue']}')\""
      } elsif ($data['queue'] == 'out') {
        $cmd = "ufw ${data['action']} ${data['queue']} to ${data['to']} port ${data['port']}"
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
