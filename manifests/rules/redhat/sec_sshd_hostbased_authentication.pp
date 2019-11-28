# @summary 
#    Ensure SSH HostbasedAuthentication is disabled (Scored)
#
# The HostbasedAuthentication parameter specifies if authentication is allowed through trusted hosts via the user 
# of .rhosts , or /etc/hosts.equiv , along with successful public key client host authentication. This option only 
# applies to SSH Protocol Version 2.
#
# Rationale:
# Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf , disabling the ability to 
# use .rhosts files in SSH provides an additional layer of protection .
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
#   class security_baseline::rules::sec_sshd_hostbased_authentication {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_sshd_hostbased_authentication (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if(
    ($facts['security_baseline']['sshd']['package']) and
    ($facts['security_baseline']['sshd']['protocol'] == '2')
  ) {
    if($enforce) {
      file_line { 'ssh-hostbased-auth':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'HostbasedAuthentication no',
        match  => '^HostbasedAuthentication.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['hostbasedauthentication'] != 'no') {
        echo { 'sshd-hostbased-auth':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
