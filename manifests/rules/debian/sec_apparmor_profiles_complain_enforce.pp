# @summary 
#    Ensure all AppArmor Profiles are in enforce or complain mode (Scored)
#
# AppArmor profiles define what resources applications are able to access.
#
# Rationale:
# Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter 
# than the default policy, which is perfectly acceptable. This item is intended to ensure that any policies 
# that exist on the system are activated.
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
# @param mode
#    Run profiles in enforce or complain mode
#
# @example
#   class ssecurity_baseline::rules::debian::sec_apparmor_profiles_complain_enforce {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       mode => 'enforce',
#   }
#
# @api private
class security_baseline::rules::debian::sec_apparmor_profiles_complain_enforce (
  Boolean $enforce                  = true,
  String $message                   = '',
  String $log_level                 = '',
  Enum['enforce', 'complain'] $mode = 'enforce',
) {
  if($enforce) {
    if($facts['security_baseline']['apparmor']['profiles_status'] == false) {
      exec {"apparmor ${mode}":
        command => "aa-${mode} /etc/apparmor.d/*",
        path    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
      }
    }
  } else {
    if($facts['security_baseline']['apparmor']['profiles_status'] == false) {
      echo { 'apparmor-profiles-enforce-complain':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
