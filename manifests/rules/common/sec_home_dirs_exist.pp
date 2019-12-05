# @summary 
#    Ensure all users' home directories exist (Scored)
#
# Users can be defined in /etc/passwd without a home directory or with a home directory that does not actually exist.
#
# Rationale:
# If the user's home directory does not exist or is unassigned, the user will be placed in "/" and will not be able to 
# write any files or have local environment variables set.
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
#   class security_baseline::rules::common::sec_home_dirs_exist {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_home_dirs_exist (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['user_home_dirs'] != 'none') {
      echo { 'users-home-dirs-exist':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
