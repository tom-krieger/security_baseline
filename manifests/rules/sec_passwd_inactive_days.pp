# @summary 
#    Ensure inactive password lock is 30 days or less (Scored)
#
# User accounts that have been inactive for over a given period of time can be automatically disabled. 
# It is recommended that accounts that are inactive for 30 days after password expiration be disabled.
# 
# Rationale:
# Inactive accounts pose a threat to system security since the users are not logging in to notice failed 
# login attempts or other anomalies.
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
#   class security_baseline::special_rules::sec_passwd_inactive_days {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::sec_passwd_inactive_days (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
  Integer $inactive_pass_days = 30,
) {
  if($enforce) {
    $local_users = pick($facts['local_users'], {})

    $local_users.each |String $user, Hash $attributes| {
      if ($attributes['password_expires_days'] != 'never') and
          ($attributes['password_expires_days'] != 'password must be changed') and
          ($attributes['password_inactive_days'] != $inactive_pass_days) {
        exec { "/bin/chage --inactive ${inactive_pass_days} ${user}": }
      }
    }
    exec { "/sbin/useradd -f ${inactive_pass_days}": }
  } else {
    if($facts['security_baseline']['pw_data']['inactive_status']) {
      echo { 'pass-warn-days':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
