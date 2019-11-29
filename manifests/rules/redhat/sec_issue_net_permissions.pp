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
#   class security_baseline::rules::redhat::sec_issue_net_permissions {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_issue_net_permissions (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    unless(defined(File['/etc/issue.net'])) {
      file { '/etc/issue.net':
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }
    }

  } else {
    if($facts['security_baseline']['issue']['net']['combined'] != '0-0-420') {
      echo { 'issue-os-uid':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
