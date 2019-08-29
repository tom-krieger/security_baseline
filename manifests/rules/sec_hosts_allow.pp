# @summary 
#    Ensure /etc/hosts.allow is configured (Scored)
#
# The /etc/hosts.allow file specifies which IP addresses are permitted to connect to the host. 
# It is intended to be used in conjunction with the /etc/hosts.deny file.
#
# Rationale:
# The /etc/hosts.allow file supports access control by IP and helps ensure that only authorized 
# systems can connect to the system.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_hosts_allow {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_hosts_allow (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    file { '/etc/hosts.allow':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => "ALL: ${facts['networking']['network']}/${facts['networking']['netmask']}",
    }

  } else {

    if($::hosts_allow == false) {
      notify { 'hosts-allow':
        message  => $message,
        loglevel => $loglevel,
      }
    }
  }
}
