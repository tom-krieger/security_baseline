# @summary 
#    Ensure default user shell timeout is 900 seconds or less (Scored)
#
# The default TMOUT determines the shell timeout for users. The TMOUT value is measured in seconds.
#
# Rationale:
# Having no timeout value associated with a shell could allow an unauthorized user access to another user's 
# shell session (e.g. user walks away from their computer and doesn't lock the screen). Setting a timeout 
# value at least reduces the risk of this happening.
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
# @param default_timeout
#    Default timeout to set
#
# @example
#   class security_baseline::rules::redhat::sec_timeout_setting {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_timeout_setting (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  Integer $default_timeout    = 900,
) {
  if($enforce) {
    file_line { 'bashrc_tmout':
      path => '/etc/bashrc',
      line => "TMOUT=${default_timeout}",
    }

    file_line { 'profile_tmout':
      path => '/etc/profile',
      line => "TMOUT=${default_timeout}",
    }
  } else {
    if($facts['security_baseline']['timeout']) {
      echo { 'timeout-setting':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
