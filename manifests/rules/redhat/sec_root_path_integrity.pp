# @summary 
#    Ensure root PATH Integrity (Scored)
#
# The root user can execute any command on the system and could be fooled into executing programs unintentionally if the PATH 
# is not set correctly.
#
# Rationale:
# Including the current working directory (.) or other writable directory in root 's executable path makes it likely that an 
# attacker can gain superuser access by forcing an administrator operating as root to execute a Trojan horse program.
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
#   class security_baseline::rules::redhat::sec_root_path_integrity {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_root_path_integrity (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['root_path_integrity'] != 'none') {
      echo { 'root-path-integrity':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
