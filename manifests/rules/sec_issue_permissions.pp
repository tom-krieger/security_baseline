# @summary 
#    Ensure permissions on /etc/issue are configured (Scored)
#
# The contents of the /etc/issue file are displayed to users prior to login for local terminals.
#
# Rationale:
# If the /etc/issue file does not have the correct ownership it could be modified by unauthorized 
# users with incorrect or misleading information.
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
#   class security_baseline::rules::sec_issue_permissions {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_issue_permissions (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if($enforce) {

    file { '/etc/issue':
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

  }
}
