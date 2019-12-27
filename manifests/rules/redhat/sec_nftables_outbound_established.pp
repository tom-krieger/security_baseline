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
#   class security_baseline::rules::redhat::sec_nftables_outbound_established {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_nftables_outbound_established (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  String $table     = 'default',
) {
  if($enforce) {
    if(has_key($facts['security_baseline'], 'nftables')) {
      if($facts['security_baseline']['nftables']['conns']['in_tcp'] == false) {
        exec { 'add nftables rule for input tcp established':
          command => "nft add rule ${table} filter input ip protocol tcp ct state established accept",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
      if($facts['security_baseline']['nftables']['conns']['in_udp'] == false) {
        exec { 'add nftables rule for input udp established':
          command => "nft add rule ${table} filter input ip protocol udp ct state established accept",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
      if($facts['security_baseline']['nftables']['conns']['in_icmp'] == false) {
        exec { 'add nftables rule for input icmp established':
          command => "nft add rule ${table} filter input ip protocol icmp ct state established accept",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
      if($facts['security_baseline']['nftables']['conns']['out_tcp'] == false) {
        exec { 'add nftables rule for output tcp established':
          command => "nft add rule ${table} filter output ip protocol tcp ct state new,related,established accept",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
      if($facts['security_baseline']['nftables']['conns']['out_udp'] == false) {
        exec { 'add nftables rule for output udp established':
          command => "nft add rule ${table} filter output ip protocol udp ct state new,related,established accept",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
      if($facts['security_baseline']['nftables']['conns']['out_icmp'] == false) {
        exec { 'add nftables rule for output icmp established':
          command => "nft add rule ${table} filter output ip protocol icmp ct state new,related,established accept",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
    }
  } else {
    if(has_key($facts['security_baseline'], 'nftables')) {
      if($facts['security_baseline']['nftables']['conns']['status'] == false) {
        echo { 'nftables-outbound-established':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
