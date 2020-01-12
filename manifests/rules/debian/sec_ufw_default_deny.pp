# @summary 
#    Ensure default deny firewall policy (Scored)
#
# A default deny policy on connections ensures that any unconfigured network usage will be rejected.
#
# Rationale:
# With a default accept policy the firewall will accept any packet that is not configured to be denied. 
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
# @param default_incoming
#    Default policy for incoming traffic
#
# @param default_outgoing
#    Default policy for outgoing traffic
#
# @param default_routed
#    Default policy for routed traffic
#
# @example
#   class security_baseline::rules::debian::sec_ufw_default_deny {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::debian::sec_ufw_default_deny (
  Boolean $enforce                        = true,
  String $message                         = '',
  String $log_level                       = '',
  Enum['allow', 'deny'] $default_incoming = 'allow',
  Enum['allow', 'deny'] $default_outgoing = 'allow',
  Enum['allow', 'deny'] $default_routed   = 'allow',
) {
  if ($enforce) {
    exec { "default incoming policy ${default_incoming}":
      command => "ufw default ${default_incoming} incoming",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(ufw status verbose | grep '${default_incoming} (incoming)')\"",
    }
    exec { "default outgoing policy ${default_outgoing}":
      command => "ufw default ${default_outgoing} outgoing",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(ufw status verbose | grep '${default_outgoing} (outgoing)')\"",
    }
    exec { "default routed policy ${default_routed}":
      command => "ufw default ${default_routed} routed",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test -z \"$(ufw status verbose | grep '${default_routed} (routed)')\"",
    }
  } else {
    if($facts['security_baseline']['ufw']['default_deny_status'] == false) {
      echo { 'ufw-default-deny':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
