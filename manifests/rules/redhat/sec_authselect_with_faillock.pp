# @summary 
#    Ensure authselect includes with-faillock (Scored)
#
# The pam_faillock.so module maintains a list of failed authentication attempts per user during a specified 
# interval and locks the account in case there were more than deny consecutive failed authentications. It 
# stores the failure records into per-user files in the tally directory.
#
# Rationale:
# Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password 
# attacks against your systems.
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
# @example
#   class { 'security_baseline::rules::redhat::sec_authselect_with_faillock':   
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_authselect_with_faillock (
  Boolean $enforce       = true,
  String $message        = '',
  String $log_level      = '',
) {
  if (!('with-faillock' in $facts['security_baseline']['authselect']['current_options'])) {
    echo { 'authselect-faillock':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
