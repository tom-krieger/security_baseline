# @summary 
#     Ensure default deny firewall policy (Scored)
#
# A default deny all policy on connections ensures that any unconfigured network usage will be rejected.
#
# Rationale:
# With a default accept policy the firewall will accept any packet that is not configured to be denied. It is easier 
# to white list acceptable usage than to black list unacceptable usage.
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
# @param input_policy
#    The default policy for the input chain
#
# @param output_policy
#    The default policy for the output chain
#
# @param forward_policy
# The default policy for the forward chain
#
# @example
#   class security_baseline::rules::common::sec_iptables_deny_policy {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       input_policy => 'drop',
#       output_policy => 'accept',
#       forward_policy => 'drop',
#   }
#
# @api private
class security_baseline::rules::common::sec_iptables_deny_policy (
  Boolean $enforce                       = true,
  String $message                        = '',
  String $log_level                      = '',
  Enum['drop', 'accept'] $input_policy   = 'drop',
  Enum['drop', 'accept'] $output_policy  = 'accept',
  Enum['drop', 'accept'] $forward_policy = 'drop',
) {
  if ($enforce) {
    firewallchain { 'OUTPUT:filter:IPv4':
      ensure => present,
      policy => $output_policy,
    }

    firewallchain { 'FORWARD:filter:IPv4':
      ensure => present,
      policy => $forward_policy,
    }

    firewallchain { 'INPUT:filter:IPv4':
      ensure => present,
      policy => $input_policy,
    }

    firewallchain { 'OUTPUT:filter:IPv6':
      ensure => present,
      policy => $output_policy,
    }

    firewallchain { 'FORWARD:filter:IPv6':
      ensure => present,
      policy => $forward_policy,
    }

    firewallchain { 'INPUT:filter:IPv6':
      ensure => present,
      policy => $input_policy,
    }
  } else {
    if($facts['security_baseline']['iptables']['policy_status'] == false) {
      echo { 'iptables-policy-status':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
