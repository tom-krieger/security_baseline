# @summary 
#    Ensure xinetd is not installed (Scored)
#
# The eXtended InterNET Daemon ( xinetd ) is an open source super daemon that replaced the original inetd 
# daemon. The xinetd daemon listens for well known services and dispatches the appropriate daemon to properly 
# respond to service requests.
#
# Rationale:
# If there are no xinetd services required, it is recommended that the package be removed.
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
#   class security_baseline::rules::redhat::sec_package_xinetd {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_package_xinetd (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    Package { 'xinetd':
      ensure => absent,
    }
  } else {
    if($facts['security_baseline']['packages_installed']['xinetd']) {
      echo { 'xinetd-pkg':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
