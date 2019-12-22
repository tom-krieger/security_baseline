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
  $profile_options.each |$opt| {
    if(!($opt in $facts['security_baseline']['authselect']['current_options'])) and (!$work){
      $work = true
    }
  }
  $facts['security_baseline']['authselect']['current_options'].each |$opt| {
    if(!($opt in $profile_options)) and (!$work){
      $work = true
    }
  }

  if ($enforce) {
    $options = join($profile_options, ' ')
    if($work) {
      exec { 'select authselect profile':
        command => "authselect select custom/${custom_profile} ${options}",
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    }
  } else {
    if($work) {
      echo { 'authselect-profile-select':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
