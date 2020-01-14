# @summary
#    Ensure AppArmor are installed (Scored)
#
# AppArmor provides Mandatory Access Controls.
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
#   }
#
# @api private
class security_baseline::rules::debian::sec_access_control (
  Boolean $enforce                                = true,
  String $message                                 = '',
  String $log_level                               = '',
  Enum['selinux', 'apparmor'] $access_control_pkg = 'apparmor'
) {
  if($enforce) {
    if($access_control_pkg == 'apparmor') {
      if(!defined(Package['apparmor'])) {
        package { 'apparmor':
          ensure => installed,
        }
      }
      if(!defined(Package['apparmor-utils'])) {
        package {'apparmor-utils':
          ensure  => installed,
          require => Package['apparmor'],
        }
      }
    } elsif($access_control_pkg == 'selinux') {
      if(!defined(Package['selinux-basics'])) {
        package {'selinux-basics':
          ensure => installed,
        }
      }
      if(!defined(Package['selinux-policy-default'])){
        package {'selinux-policy-default':
          ensure => installed,
        }
      }
    }
  } else {
    if($facts['security_baseline']['access_control'] == 'none') {
      echo { 'apparmor-pkg':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
