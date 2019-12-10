# @summary 
#    Ensure SSH root login is disabled (Scored)
#
# The PermitRootLogin parameter specifies if the root user can log in using ssh(1). The default is no.
#
# Rationale:
# Disallowing root logins over SSH requires system admins to authenticate using their own individual account, 
# then escalating to root via sudo or su . This in turn limits opportunity for non-repudiation and provides 
# a clear audit trail in the event of a security incident
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
#   class security_baseline::rules::common::sec_sshd_root_login {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_root_login (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'sshd-root-login':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'PermitRootLogin no',
        match  => '^PermitRootLogin.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['permitrootlogin'] != 'no') {
        echo { 'sshd-root-login':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
