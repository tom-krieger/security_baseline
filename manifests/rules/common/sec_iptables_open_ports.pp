# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline::rules::common::sec_iptables_open_ports
class security_baseline::rules::common::sec_iptables_open_ports (
  Boolean $enforce     = true,
  String $message      = '',
  String $log_level    = '',
  Hash $firewall_rules = {},
) {
  $rule10 = $facts['security_baseline']['iptables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and $data['dpt'] == 'tcp:22' and
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
