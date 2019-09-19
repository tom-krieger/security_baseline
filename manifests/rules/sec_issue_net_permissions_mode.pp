# @summary 
#    Ensure permissions on /etc/issue.net are configured (Not Scored)
#
# The contents of the /etc/issue.net file are displayed to users prior to login for 
# remote connections from configured services.
#
# Rationale:
# If the /etc/issue.net file does not have the correct ownership it could be modified 
# by unauthorized users with incorrect or misleading information.
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
#   class security_baseline::rules::sec_issue_net_permissions_mode {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_issue_net_permissions_mode (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if(!$enforce) and ($facts['security_baseline']['issue']['net']['mode'] != 0644) {
    echo { 'issue-os-mode':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
