# @summary 
#    Ensure SSH PAM is enabled (Scored)
#
# UsePAM Enables the Pluggable Authentication Module interface. If set to “yes” this will 
# enable PAM authentication using ChallengeResponseAuthentication and PasswordAuthentication 
# in addition to PAM account and session module processing for all authentication types.
#
# Rationale:
# When usePAM is set to yes, PAM runs through account and session types properly. This is 
# important if you want to restrict access to services based off of IP, time or other factors 
# of the account. Additionally, you can make sure users inherit certain environment variables 
# on login or disallow access to the server
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
#   class security_baseline::rules::common::sec_sshd_use_pam {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_use_pam (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'sshd-use-pam':
      ensure             => present,
      path               => '/etc/ssh/sshd_config',
      line               => 'UsePAM yes',
      match              => '^UsePAM.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  } else {
    if($facts['security_baseline']['sshd']['usepam'] != 'yes') {
        echo { 'sshd-use-pam':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
  }
}
