# @summary 
#    Ensure system accounts are non-login (Scored)
#
# There are a number of accounts provided with Red Hat 7 that are used to manage applications and are not 
# intended to provide an interactive shell.
#
# Rationale:
# It is important to make sure that accounts that are not being used by regular users are prevented from 
# being used to provide an interactive shell. By default Red Hat 7 sets the password field for these accounts 
# to an invalid string, but it is also recommended that the shell field in the password file be set to /sbin/nologin . 
# This prevents the account from potentially being used to run any commands.
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
# @param max_pass_days
#    Password expires after days
#
# @example
#   class security_baseline::special_rules::sec_shell_nologin {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::sec_shell_nologin (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
) {
  if($enforce) {
    if(!empty($facts['security_baseline']['accounts']['no_shell_nologin'])) {
      $facts['security_baseline']['accounts']['no_shell_nologin'].each | String $user | {
        exec { "nologin ${user}":
          command => "usermod -s /sbin/nologin ${user}",
          path    => '/sbin/',
        }
      }
    }
  } else {
    if($facts['security_baseline']['accounts']['no_shell_nologin_count'] != 0) {
      echo { 'nologin-shell':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
