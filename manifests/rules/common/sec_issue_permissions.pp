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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::common::sec_issue_permissions {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_issue_permissions (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    unless(defined(File['/etc/issue'])) {
      file { '/etc/issue':
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }
    }

  } else {
    if($facts['security_baseline']['issue']['os']['combined'] != '0-0-420') {
      echo { 'issue-os-perms':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
