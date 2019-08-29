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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_issue_net_permissions {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_issue_net_permissions (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    file { '/etc/issue.net':
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

  }
}
