# @summary 
#    Create custom authselect profile (Scored)
#
# A custom profile can be created by copying and customizing one of the default profiles. The default 
# profiles include: sssd, winbind, or the nis.
#
# Rationale:
# A custom profile is required to customize many of the pam options.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param message
#    Message to print into the log
#
# @param log_level
#    Loglevel for the message
#
# @param custom_profile
#    name of the custom profile to create
#
# @param base_profile
#    Base profile to use for custom profile creation
#
# @example
#   class { 'security_baseline::rules::redhat::sec_authselect_profile':   
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#             custom_profile => 'testprofile',
#             base_profile => 'sssd',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_authselect_profile (
  Boolean $enforce                             = true,
  String $message                              = '',
  String $log_level                            = '',
  String $custom_profile                       = '',
  Enum['sssd', 'nis', 'winbind'] $base_profile = 'sssd',
) {
  if ($enforce) {
    exec { 'set custom profile':
      command => "authselect create-profile ${custom_profile} -b ${base_profile} --symlink-meta",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => "test $(authselect current | grep \"Profile ID: custom/\" | cut -f 2 -d '/') != '${custom_profile}'"
    }
  } else {
    if ($facts['security_baseline']['authselect']['profile'] == 'none') {
      echo { 'authselect-profile':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
