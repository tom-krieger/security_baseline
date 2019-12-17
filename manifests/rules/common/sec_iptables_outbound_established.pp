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
    firewall { '004 accept outbound tcp state new, established':
      chain  => 'OUTPUT',
      proto  => 'tcp',
      state  => ['NEW', 'ESTABLSHED'],
      action => 'accept',
    }
    firewall { '005 accept outbound udp state new, established':
      chain   => 'OUTPUT',
      proto   => 'udp',
      state   => ['NEW', 'ESTABLSHED'],
      action  => 'accept',
      require => Firewall['004 accept outbound tcp state new, established'],
    }
    firewall { '006 accept outbound icmp state new, established':
      chain   => 'OUTPUT',
      proto   => 'icmp',
      state   => ['NEW', 'ESTABLSHED'],
      action  => 'accept',
      require => Firewall['005 accept outbound udp state new, established'],
    }
    firewall { '007 accept inbound tcp state established':
      chain   => 'INPUT',
      proto   => 'tcp',
      state   => 'ESTABLISHED',
      action  => 'accept',
      require => Firewall['006 accept outbound icmp state new, established'],
    }
    firewall { '008 accept inbound udp state established':
      chain   => 'INPUT',
      proto   => 'udp',
      state   => 'ESTABLISHED',
      action  => 'accept',
      require => Firewall['007 accept inbound tcp state established'],
    }
    firewall { '009 accept inbound icmp state established':
      chain   => 'INPUT',
      proto   => 'icmp',
      state   => 'ESTABLISHED',
      action  => 'accept',
      require => Firewall['008 accept inbound udp state established'],
    }
  } else {

  }
}
