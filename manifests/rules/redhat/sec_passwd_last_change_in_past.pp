# @summary 
#    Ensure all users last password change date is in the past (Scored)
#
# All users should have a password change date in the past.
#
# Rationale:
# If a users recorded password change date is in the future then they could bypass any set password 
# expiration.
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
# @param max_pass_days
#    Password expires after days
#
# @example
#   class security_baseline::rules::redhat::sec_passwd_last_change_in_past {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_passwd_last_change_in_past (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
) {
  if($enforce) {
    $local_users = pick($facts['local_users'], {})

    $local_users.each |String $user, Hash $attributes| {

      if !$attributes['password_date_valid'] {
        echo { "plcd ${user}":
          message  => 'We believe the user has a password last changed date in the future.',
          loglevel => 'warning',
          withpath => false,
        }
      }
    }
  } else {
    if($facts['security_baseline']['pw_data']['pw_change_in_future']) {
      echo { 'pass-warn-days':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
