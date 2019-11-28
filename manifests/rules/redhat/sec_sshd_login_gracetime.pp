# @summary 
#    Ensure SSH LoginGraceTime is set to one minute or less (Scored)
#
# The LoginGraceTime parameter specifies the time allowed for successful authentication to the SSH server. 
# The longer the Grace period is the more open unauthenticated connections can exist. Like other session 
# controls in this session the Grace Period should be limited to appropriate organizational limits to 
# ensure the service is available for needed access.
# Rationale:
# Setting the LoginGraceTime parameter to a low number will minimize the risk of successful brute force attacks 
# to the SSH server. It will also limit the number of concurrent unauthenticated connections While the recommended 
# setting is 60 seconds (1 Minute), set the number based on site policy.
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
#   class security_baseline::rules::redhat::sec_sshd_login_gracetime {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_sshd_login_gracetime (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'ssh-login-gracetime':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'LoginGraceTime 60',
        match  => '^LoginGraceTime.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['logingracetime'] != '60') {
        echo { 'sshd-login-gracetime':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
