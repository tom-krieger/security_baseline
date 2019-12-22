# @summary 
#    Ensure SSH MaxAuthTries is set to 4 or less (Scored)
#
# The MaxAuthTries parameter specifies the maximum number of authentication attempts permitted per connection. 
# When the login failure count reaches half the number, error messages will be written to the syslog file 
# detailing the login failure.
#
# Rationale:
# Setting the MaxAuthTries parameter to a low number will minimize the risk of successful brute force attacks to 
# the SSH server. While the recommended setting is 4, set the number based on site policy.
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
#   class security_baseline::rules::common::sec_sshd_max_auth_tries {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_max_auth_tries (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'sshd-max-auth-tries':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'MaxAuthTries 4',
        match  => '^MaxAuthTries.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['maxauthtries'] != '4') {
        echo { 'sshd-max-auth-tries':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
