# @summary 
#    Ensure loopback traffic is configured (Scored)
#
# Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic 
# to the loopback network.
#
# Rationale:
# Loopback traffic is generated between processes on machine and is typically critical to operation of 
# the system. The loopback interface is the only place that loopback network traffic should be seen, 
# all other interfaces should ignore traffic on this network as an anti- spoofing measure.
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
#   class security_baseline::rules::redhat::sec_nftables_loopback {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_nftables_loopback (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if($enforce) {
    if($facts['security_baseline']['nftables']['loopback']['lo_iface'] == 'none') {
      exec { 'nftables add local interface':
        command => 'nft add rule inet filter input iif lo accept',
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    }
    if($facts['security_baseline']['nftables']['loopback']['lo_network'] == 'none') {
      exec { 'nftables add local network':
        command => 'nft create rule inet filter input ip saddr 127.0.0.0/8 counter drop',
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    }
    if($facts['security_baseline']['nftables']['loopback']['ip6_saddr'] == 'none') {
      exec { 'nftables ip6 traffic':
        command => 'nft add rule inet filter input ip6 saddr ::1 counter drop',
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    }
  } else {
    if($facts['security_baseline']['nftables']['loopback']['status'] == false) {
      echo { 'nftables-loopback':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
