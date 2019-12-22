# @summary 
#    Ensure SSH MaxStartups is configured (Scored)
#
# The MaxStartups parameter specifies the maximum number of concurrent unauthenticated connections 
# to the SSH daemon.
#
# Rationale:
# To protect a system from denial of service due to a large number of pending authentication connection 
# attempts, use the rate limiting function of MaxStartups to protect availability of sshd logins and 
# prevent overwhelming the daemon.
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
#   class security_baseline::rules::common::sec_sshd_max_startups {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_max_startups (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'sshd-max-startups':
      ensure             => present,
      path               => '/etc/ssh/sshd_config',
      line               => 'maxstartups 10:30:60',
      match              => '^maxstartups.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  } else {
    if($facts['security_baseline']['sshd']['maxstartups'] != 'yes') {
        echo { 'sshd-max-startups':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
  }
}
