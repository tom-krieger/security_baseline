# @summary 
#    Ensure SSH PermitUserEnvironment is disabled (Scored)
#
# The PermitUserEnvironment option allows users to present environment options to the ssh daemon.
#
# Rationale:
# Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to 
# bypass security controls (e.g. setting an execution path that has ssh executing trojan'd programs)
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
#   class security_baseline::rules::common::sec_sshd_user_environment {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_user_environment (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'sshd-user-environment':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'PermitUserEnvironment no',
        match  => '^PermitUserEnvironment.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['permituserenvironment'] != 'no') {
        echo { 'sshd-user-environment':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
