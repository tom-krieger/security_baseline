# @summary 
#    Ensure firewall rules exist for all open ports (Scored)
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
#    Additional firewall rules to setup
#
# @example
#   class security_baseline::rules::common::sec_iptables_outbound_established {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       firewall_rules => {},
#   }
#
# @api private
class security_baseline::rules::common::sec_iptables_open_ports (
  Boolean $enforce     = true,
  String $message      = '',
  String $log_level    = '',
  Hash $firewall_rules = {},
) {
  $rule10 = $facts['security_baseline']['iptables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and $data['dpt'] == '22' and
    $data['state'] == 'NEW' and $data['target'] == 'ACCEPT'
  }
  if ($enforce) {
    if(empty($firewall_rules)) {
      if ($rule10.empty) {
        firewall { '010 open ssh port inbound':
          chain  => 'INPUT',
          proto  => 'tcp',
          dport  => 22,
          state  => 'NEW',
          action => 'accept',
        }
      }
    } else {
      $firewall_rules.each | String $rulename, Hash $data | {
        firewall { $rulename:
          * => $data,
        }
      }
    }
  } else {
    if ($rule10.empty) {
      echo { 'iptables-open-ports':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
