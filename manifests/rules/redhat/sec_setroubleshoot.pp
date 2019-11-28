# @summary 
#    Ensure SETroubleshoot is not installed (Scored)
#
# The SETroubleshoot service notifies desktop users of SELinux denials through a user- friendly interface. 
# The service provides important information around configuration errors, unauthorized intrusions, and other 
# potential errors.
#
# Rationale:
# The SETroubleshoot service is an unnecessary daemon to have running on a server, especially if X Windows is disabled.
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
#   class security_baseline::rules::redhat::sec_setroubleshoot {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_setroubleshoot (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {

  if($enforce) {

    if $facts['os']['name'].downcase() == 'sles' {
      $action = 'absent'
    } else {
      $action = 'purged'
    }
    package { 'setroubleshoot':
      ensure => $action,
    }

  } else {

    if($facts['security_baseline']['packages_installed']['setroubleshoot']) {

      echo { 'setroubleshoot':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
