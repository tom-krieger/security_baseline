# @summary 
#    Ensure base chains exist (Scored)
#
# Chains are containers for rules. They exist in two kinds, base chains and regular chains. A base chain is an 
# entry point for packets from the networking stack, a regular chain may be used as jump target and is used 
# for better rule organization.
#
# Rationale:
# If a base chain doesn't exist with a hook for input, forward, and delete, packets that would flow through 
# those chains will not be touched by nftables.
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
#   class security_baseline::rules::debian::sec_nftables_base_chains {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::debian::sec_nftables_base_chains (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  String $table     = 'default',
) {
  if($enforce) {
    exec { 'create base chain input':
      command => "nft create chain ${table} filter input { type filter hook input priority 0 \\; }",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'type filter hook input priority 0')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'create base chain forward':
      command => "nft create chain ${table} filter forward { type filter hook forward priority 0 \\; }",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'type filter hook forward priority 0')\"",
      notify  => Exec['dump nftables ruleset'],
    }

    exec { 'create base chain output':
      command => "nft create chain ${table} filter output { type filter hook output priority 0 \\; }",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(nft list ruleset ${table} | grep 'type filter hook output priority 0')\"",
      notify  => Exec['dump nftables ruleset'],
    }

  } else {
    if(has_key($facts['security_baseline'], 'nftables')) {
      if($facts['security_baseline']['nftables']['base_chain_status'] == false) {
        echo { 'nftables-base-chains':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
