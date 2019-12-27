# @summary 
#     Ensure default deny firewall policy (Scored)
#
# Base chain policy is the default verdict that will be applied to packets reaching the end of the chain.
#
# Rationale:
# There are two policies: accept (Default) and drop. If the policy is set to accept, the firewall will 
# accept any packet that is not configured to be denied and the packet will continue transversing the 
# network stack.
# It is easier to white list acceptable usage than to black list unacceptable usage.
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
# @param default_policy_input
#    Default input policy
#
# @param default_policy_forward
#    Default forward policy
#
# @param default_policy_output
#    Default output policy
#
# @example
#   class security_baseline::rules::redhat::sec_nftables_default_deny {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_nftables_default_deny (
  Boolean $enforce                                         = true,
  String $message                                          = '',
  String $log_level                                        = '',
  Enum['accept', 'reject', 'drop'] $default_policy_input   = 'drop',
  Enum['accept', 'reject', 'drop'] $default_policy_output  = 'drop',
  Enum['accept', 'reject', 'drop'] $default_policy_forward = 'drop',
  String $table                                            = 'default',
  Array $additional_rules                                  = [],
) {
  if($enforce) {
    if(has_key($facts['security_baseline'], 'nftables')) {
      if($facts['security_baseline']['nftables']['policy']['input'] != $default_policy_input) {
        exec { 'set input default policy':
          command => "nft chain ${table} filter input { policy ${default_policy_input} \; }",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
      if($facts['security_baseline']['nftables']['policy']['forward'] != $default_policy_forward) {
        exec { 'set forward default policy':
          command => "nft chain ${table} filter forward { policy ${default_policy_forward} \; }",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }
      if($facts['security_baseline']['nftables']['policy']['output'] != $default_policy_output) {
        exec { 'set output default policy':
          command => "nft chain ${table} filter output { policy ${default_policy_output} \; }",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
        }
      }

      $additional_rules.each |$rule| {
        exec { $rule:
          command => "nft add rule ${table} ${rule}",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          onlyif  => "test -z \"$(nft list ruleset | grep '${rule}')\"",
        }
      }
    }
  } else {
    if(has_key($facts['security_baseline'], 'nftables')) {
      if($facts['security_baseline']['nftables']['policy']['status'] == false) {
        echo { 'nftables-default-deny':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
