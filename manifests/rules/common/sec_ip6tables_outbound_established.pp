# @summary 
#    Ensure outbound and established connections are configured (Not Scored)
#
# Configure the firewall rules for new outbound, and established connections.
#
# Rationale:
# If rules are not in place for new outbound, and established connections all packets will be dropped 
# by the default policy preventing network usage.
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
#   class security_baseline::rules::common::sec_ip6tables_outbound_established {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::common::sec_ip6tables_outbound_established (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  $rule4 = $facts['security_baseline']['ip6tables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'OUTPUT' and $data['proto'] == 'tcp' and
    $data['state'] == 'NEW,ESTABLISHED' and $data['target'] == 'ACCEPT'
  }
  $rule5 = $facts['security_baseline']['ip6tables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'OUTPUT' and $data['proto'] == 'udp' and
    $data['state'] == 'NEW,ESTABLISHED' and $data['target'] == 'ACCEPT'
  }
  $rule6 = $facts['security_baseline']['ip6tables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and
    $data['state'] == 'ESTABLISHED' and $data['target'] == 'ACCEPT'
  }
  $rule7 = $facts['security_baseline']['ip6tables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and
    $data['state'] == 'ESTABLISHED' and $data['target'] == 'ACCEPT'
  }
  $rule8 = $facts['security_baseline']['ip6tables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'INPUT' and $data['proto'] == 'udp' and
    $data['state'] == 'ESTABLISHED' and $data['target'] == 'ACCEPT'
  }
  $rule9 = $facts['security_baseline']['ip6tables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'INPUT' and $data['proto'] == 'tcp' and
    $data['state'] == 'ESTABLISHED' and $data['target'] == 'ACCEPT'
  }

  if ($enforce) {
    firewall { '004-6 accept outbound tcp state new, established':
      chain    => 'OUTPUT',
      proto    => 'tcp',
      state    => ['NEW', 'ESTABLISHED'],
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '005-6 accept outbound udp state new, established':
      chain    => 'OUTPUT',
      proto    => 'udp',
      state    => ['NEW', 'ESTABLISHED'],
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '006-6 accept outbound icmp state new, established':
      chain    => 'OUTPUT',
      proto    => 'icmp',
      state    => ['NEW', 'ESTABLISHED'],
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '007-6 accept inbound tcp state established':
      chain    => 'INPUT',
      proto    => 'tcp',
      state    => 'ESTABLISHED',
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '008-6 accept inbound udp state established':
      chain    => 'INPUT',
      proto    => 'udp',
      state    => 'ESTABLISHED',
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '009-6 accept inbound icmp state established':
      chain    => 'INPUT',
      proto    => 'icmp',
      state    => 'ESTABLISHED',
      action   => 'accept',
      provider => 'ip6tables',
    }
  } else {
    if ($rule4.empty or $rule5.empty or $rule6.empty or $rule7.empty or $rule8.empty or $rule9.empty) {
      echo { 'ip6tables-outbound-established':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
