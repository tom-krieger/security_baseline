# @summary 
#     Ensure loopback traffic is configured (Scored)
#
# Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the 
# loopback network (127.0.0.0/8).
#
# Rationale:
# Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The 
# loopback interface is the only place that loopback network (127.0.0.0/8) traffic should be seen, all other interfaces 
# should ignore traffic on this network as an anti-spoofing measure.
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
#   class security_baseline::rules::common::sec_ip6tables_loopback {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::common::sec_ip6tables_loopback (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  $rule1 = $facts['security_baseline']['ip6tables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'INPUT' and $data['proto'] == 'all' and $data['in'] == 'lo' and
    $data['src'] == '0.0.0.0/0' and $data['dst'] == '0.0.0.0/0' and $data['target'] == 'ACCEPT'
  }
  $rule2 = $facts['security_baseline']['ip6tables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'OUTPUT' and $data['proto'] == 'all' and $data['out'] == 'lo' and
    $data['src'] == '0.0.0.0/0' and $data['dst'] == '0.0.0.0/0' and $data['target'] == 'ACCEPT'
  }
  $rule3 = $facts['security_baseline']['ip6tables']['policy'].filter |$rule, $data| {
    $data['chain'] == 'INPUT' and $data['proto'] == 'all' and
    $data['src'] == '127.0.0.0/8' and $data['dst'] == '0.0.0.0/0' and $data['target'] == 'DROPI'
  }
  if ($enforce) {
    firewall { '001-6 accept all incoming traffic to local interface':
      chain    => 'INPUT',
      proto    => 'all',
      iniface  => 'lo',
      action   => 'accept',
      provider => 'ip6tables',
    }
    firewall { '002-6 accept all outgoing traffic to local interface':
      chain    => 'OUTPUT',
      proto    => 'all',
      outiface => 'lo',
      action   => 'accept',
      provider => 'ip6tables',
    }

    firewall { '003-6 drop all traffic to lo ::1':
      chain    => 'INPUT',
      proto    => 'all',
      source   => '::1',
      action   => 'drop',
      provider => 'ip6tables',
    }
  } else {
    if $rule1.empty or $rule2.empty or $rule3.empty {
      echo { 'ip6tables-loopback':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
