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
  if ($enforce) {
    if(empty($firewall_rules)) {
      firewall { '010 open ssh port inbound':
        chain  => 'INPUT',
        proto  => 'tcp',
        dport  => 22,
        state  => 'NEW',
        action => 'accept',
      }
    } else {
      $firewall_rules.each | String $rulename, Hash $data | {
        firewall { $rulename:
          * => $data,
        }
      }
    }
  } else {

  }
}
