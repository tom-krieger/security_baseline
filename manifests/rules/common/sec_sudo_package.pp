# @summary 
#    Ensure sudo is installed (Scored)
#
# sudo allows a permitted user to execute a command as the superuser or another user, as specified by the 
# security policy. The invoking user's real (not effective) user ID is used to determine the user name 
# with which to query the security policy.
# 
# Rationale:
# sudo supports a plugin architecture for security policies and input/output logging. Third parties can 
# develop and distribute their own policy and I/O logging plugins to work seamlessly with the sudo front 
# end. The default security policy is sudoers, which is configured via the file /etc/sudoers.
#
# The security policy determines what privileges, if any, a user has to run sudo. The policy may require 
# that users authenticate themselves with a password or another authentication mechanism. If authentication 
# is required, sudo will exit if the user's password is not entered within a configurable time limit. This 
# limit is policy-specific.
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
#   class security_baseline::rules::common::sec_sudo_package {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sudo_package (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    if(!defined(Package['sudo'])) {
      ensure_packages(['sudo'], {
        ensure => installed,
      })
    }
  } else {
    if ($facts['security_baseline']['packages_installed']['sudo'] == false) {
      echo { 'sudo-package':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
