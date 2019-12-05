# @summary 
#    Ensure password fields are not empty (Scored)
#
# An account with an empty password field means that anybody may log in as that user without providing a password.
#
# Rationale:
# All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
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
#   class security_baseline::rules::common::sec_empty_passwords {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_empty_passwords (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['empty_passwords'] != 'none') {
      echo { 'empty-passwords':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
