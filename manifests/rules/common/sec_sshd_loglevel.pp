# @summary 
#    Ensure SSH LogLevel is set to INFO (Scored)
#
# The INFO parameter specifies that login and logout activity will be logged. 
#
# Rationale:
# SSH provides several logging levels with varying amounts of verbosity. DEBUG is specifically not recommended other 
# than strictly for debugging SSH communications since it provides so much data that it is difficult to identify 
# important security information. INFO level is the basic level that only records login activity of SSH users. In many 
# situations, such as Incident Response, it is important to determine when a particular user was active on a system. 
# The logout record can eliminate those users who disconnected, which helps narrow the field.
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
#   class security_baseline::rules::common::sec_sshd_loglevel {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_loglevel (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'sshd-loglevel':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'LogLevel INFO',
        match  => '^LogLevel.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['loglevel'] != 'INFO') {
        echo { 'sshd-loglevel':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
