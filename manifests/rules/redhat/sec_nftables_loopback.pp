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
# @param table
#    nftable table to add rules
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
  String $table     = 'default',
) {
  if($enforce) {
    exec { 'nftables add local interface':
      command => "nft add rule ${table} filter input iif lo accept",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'iif \"lo\" accept')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'nftables add local network':
      command => "nft add rule ${table} filter input ip saddr 127.0.0.0/8 counter drop",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep -E 'ip\\s*saddr\\s*127.0.0.0/8\\s*counter\\s*packets.*drop')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'nftables ip6 traffic':
      command => "nft add rule ${table} filter input ip6 saddr ::1 counter drop",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'ip6 saddr ::1 counter packets')\"",
      notify  => Exec['dump nftables ruleset'],
    }
  } else {
    if(has_key($facts['security_baseline'], 'nftables')) {
      if($facts['security_baseline']['nftables'][$table]['loopback']['status'] == false) {
        echo { 'nftables-loopback':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
