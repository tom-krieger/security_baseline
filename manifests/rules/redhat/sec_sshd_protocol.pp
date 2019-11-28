# @summary 
#    Ensure SSH Protocol is set to 2 (Scored)
#
# SSH supports two different and incompatible protocols: SSH1 and SSH2. SSH1 was the original 
# protocol and was subject to security issues. SSH2 is more advanced and secure.
#
# Rationale:
# SSH v1 suffers from insecurities that do not affect SSH v2.
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
#   class security_baseline::rules::sec_sshd_protocol {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_sshd_protocol (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'ssh-protocol':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'Protocol 2',
        match  => '^Protocol.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['protocol'] != '2') {
        echo { 'sshd-protocol':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
