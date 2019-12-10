# @summary 
#    Ensure no users have .forward files (Scored)
#
# The .forward file specifies an email address to forward the user's mail to. 
#
# Rationale:
# Use of the .forward file poses a security risk in that sensitive data may be inadvertently transferred 
# outside the organization. The .forward file also poses a risk as it can be used to execute commands that 
# may perform unintended actions.
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
#   class security_baseline::rules::common::sec_users_forward_files {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_users_forward_files (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($facts['security_baseline']['forward_files'] != 'none') {
    echo { 'user-forward-files':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
