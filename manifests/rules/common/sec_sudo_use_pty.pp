# @summary 
#    Ensure sudo commands use pty (Scored)
#
# sudo can be configured to run only from a psuedo-pty
#
# Rationale:
# Attackers can run a malicious program using sudo which would fork a background process 
# that remains even when the main program has finished executing.
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
#   class security_baseline::rules::common::sec_sudo_use_pty {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sudo_use_pty (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'sudo use pty':
      path               => '/etc/sudoers',
      match              => 'Defaults.*use_pty',
      append_on_no_match => true,
      line               => 'Defaults use_pty',
    }
  } else {
    if ($facts['security_baseline']['sudo']['use_pty'] == 'none') {
      echo { 'sudo-use-pty':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
