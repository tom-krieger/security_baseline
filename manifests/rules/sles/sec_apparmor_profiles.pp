# @summary 
#    Ensure all AppArmor Profiles are enforcing (Scored)
#
# AppArmor profiles define what resources applications are able to access.
#
#Rationale:
# Security configuration requirements vary from site to site. Some sites may mandate a policy that is 
# stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that 
# any policies that exist on the system are activated.
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
#   class ssecurity_baseline::rules::sles::sec_apparmor_profiles {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::sles::sec_apparmor_profiles (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    if($facts['security_baseline']['apparmor']['profiles'] != $facts['security_baseline']['apparmor']['profiles_enforced']) {
      if(!defined(Package['apparmor'])) {
        ensure_packages(['apparmor'], {
          ensure => installed,
        })
      }
      ensure_packages(['apparmor-utils'], {
        ensure  => installed,
        require => Package['apparmor'],
      })
      exec {'apparmor enforce':
        command => 'enforce /etc/apparmor.d/*',
        path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
        require => Package['apparmor-utils'],
      }
    }
  } else {
    if($facts['security_baseline']['apparmor']['profiles'] != $facts['security_baseline']['apparmor']['profiles_enforced']) {
      echo { 'apparmor-profiles':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
