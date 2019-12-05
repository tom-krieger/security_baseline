# @summary 
#    Ensure SSH warning banner is configured (Scored)
#
# The Banner parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. 
# By default, no banner is displayed.
#
# Rationale:
# Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning 
# message prior to the normal user login may assist the prosecution of trespassers on the computer system.
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
#   class security_baseline::rules::common::sec_sshd_banner {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_banner (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'ssh-banner':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'Banner /etc/issue.net',
        match  => '^Banner.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['banner'] == 'none') {
        echo { 'sshd-banner':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
