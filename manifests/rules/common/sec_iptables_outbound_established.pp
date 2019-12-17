# @summary A short summary of the purpose of this class
#
# A description of what this class does
#
# @example
#   include security_baseline::rules::common::sec_iptables_outbound_established
class security_baseline::rules::common::sec_iptables_outbound_established (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if ($enforce) {
    $rule4 = $facts['security_baseline']['iptables']['policy'].filter |$rule, $data| {
      $data['chain'] == 'OUTPUT' and $data['proto'] == 'tcp' and
      $data['state'] == 'NEW,ESTABLISHED' and $data['target'] == 'ACCEPT'
    }
    $rule5 = $facts['security_baseline']['iptables']['policy'].filter |$rule, $data| {
      $data['chain'] == 'OUTPUT' and $data['proto'] == 'udp' and
      $data['state'] == 'NEW,ESTABLISHED' and $data['target'] == 'ACCEPT'
    }
    $rule6 = $facts['security_baseline']['iptables']['policy'].filter |$rule, $data| {
      $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and
      $data['state'] == 'ESTABLISHED' and $data['target'] == 'ACCEPT'
    }
    $rule7 = $facts['security_baseline']['iptables']['policy'].filter |$rule, $data| {
      $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and
      $data['state'] == 'ESTABLISHED' and $data['target'] == 'ACCEPT'
    }
    $rule8 = $facts['security_baseline']['iptables']['policy'].filter |$rule, $data| {
      $data['chain'] == 'INPUT' and $data['proto'] == 'udp' and
      $data['state'] == 'ESTABLISHED' and $data['target'] == 'ACCEPT'
    }
    $rule9 = $facts['security_baseline']['iptables']['policy'].filter |$rule, $data| {
      $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and
      $data['state'] == 'ESTABLISHED' and $data['target'] == 'ACCEPT'
    }

    firewall { '004 accept outbound tcp state new, established':
      chain  => 'OUTPUT',
      proto  => 'tcp',
      state  => ['NEW', 'ESTABLISHED'],
      action => 'accept',
    }
    firewall { '005 accept outbound udp state new, established':
      chain  => 'OUTPUT',
      proto  => 'udp',
      state  => ['NEW', 'ESTABLISHED'],
      action => 'accept',
    }
    firewall { '006 accept outbound icmp state new, established':
      chain  => 'OUTPUT',
      proto  => 'icmp',
      state  => ['NEW', 'ESTABLISHED'],
      action => 'accept',
    }
    firewall { '007 accept inbound tcp state established':
      chain  => 'INPUT',
      proto  => 'tcp',
      state  => 'ESTABLISHED',
      action => 'accept',
    }
    firewall { '008 accept inbound udp state established':
      chain  => 'INPUT',
      proto  => 'udp',
      state  => 'ESTABLISHED',
      action => 'accept',
    }
    firewall { '009 accept inbound icmp state established':
      chain  => 'INPUT',
      proto  => 'icmp',
      state  => 'ESTABLISHED',
      action => 'accept',
    }
  } else {
    if ($rule4.empty or $rule5.empty or $rule6.empty or $rule7.empty or $rule8.empty or $rule9.empty) {
      echo { 'iptables-outbound-establiched':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
