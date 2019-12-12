# @summary
#    Ensure SELinux or AppArmor are installed (Scored)
#
# SELinux and AppArmor provide Mandatory Access Controls.
#
# Rationale:
# Without a Mandatory Access Control system installed only the default Discretionary 
# Access Control system will be available.
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
# @param access_control_pkg
#    Install SELinux or AppArmor
#
# @example
#   class security_baseline::rules::debian::sec_access_control {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       access_control_pkg => 'selinux',
#   }
#
# @api private
class security_baseline::rules::debian::sec_access_control (
  Boolean $enforce                                = true,
  String $message                                 = '',
  String $log_level                               = '',
  Enum['selinux', 'apparmor'] $access_control_pkg = 'selinux'
) {
  if($enforce) {
    if(!defined(Package[$access_control_pkg])) {
      package { $access_control_pkg:
        ensure => present,
      }
    }
  } else {
    if($facts['security_baseline']['access_control'] == 'none') {
      echo { 'selinux-apparmor-pkg':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
