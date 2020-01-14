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
#   class security_baseline::rules::debian::sec_exim4 {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_exim4 (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    package { 'exim4':
      ensure => absent,
    }
  } else {
    if($facts['security_baseline']['packages_installed']['exim4'] == true) {
      echo { 'exim4':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
