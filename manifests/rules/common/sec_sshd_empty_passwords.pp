# @summary A short summary of the purpose of this class
#
# A description of what this class does
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
#   class security_baseline::rules::common::sec_sshd_empty_passwords {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_empty_passwords (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'ssh-empty-passwords':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'PermitEmptyPasswords no',
        match  => '^PermitEmptyPasswords.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['permitemptypasswords'] != 'no') {
        echo { 'sshd-empty-passwords':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
