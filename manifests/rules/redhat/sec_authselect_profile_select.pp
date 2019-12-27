# @summary 
#    Select authselect profile (Scored)
#
# You can select a profile for the authselect utility for a specific host. The profile 
# will be applied to every user logging into the host.
#
# You can create and deploy a custom profile by customizing one of the default profiles, the sssd, winbind, or the nis profile.
#
# Rationale:
# When you deploy a profile, the profile is applied to every user logging into the given host.
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
# @param profile_options
#    Options to use for the authselect profile
#
# @example
#   class { 'security_baseline::rules::redhat::sec_authselect_profile_select':   
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#             custom_profile => 'testprofile',
#             profile_options => ['with-sudo', 'with-faillock', 'without-nullok'],
#   }
#
# @api private
class security_baseline::rules::redhat::sec_authselect_profile_select (
  Boolean $enforce       = true,
  String $message        = '',
  String $log_level      = '',
  String $custom_profile = '',
  Array $profile_options = [],
) {
  if ($enforce) {
    $options = join($profile_options, ' ')
    exec { 'select authselect profile':
      command => "authselect select custom/${custom_profile} ${options} -f",
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => ["test -d /etc/authselect/custom/${custom_profile}",
                  "test -z \"$(authselect current | grep 'custom/${custom_profile}')\""],
      returns => [0, 1],
    }
  } else {
    $profile_options.each |$opt| {
      unless ($opt in $facts['security_baseline']['authselect']['current_options']) {
        if(!defined(Echo['authselect-profile-select'])) {
          echo { 'authselect-profile-select':
            message  => $message,
            loglevel => $log_level,
            withpath => false,
          }
        }
      }
    }
  }
}
