# @summary 
#    Ensure no unconfined daemons exist (Scored)
#
# Daemons that are not defined in SELinux policy will inherit the security context of their parent process.
#
# Rationale:
# Since daemons are launched and descend from the init process, they will inherit the security context label 
# initrc_t . This could cause the unintended consequence of giving the process more permission than it requires.
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
#   class security_baseline::rules::common::sec_unconfigured_daemons {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_unconfigured_daemons (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['unconfigured_daemons'] != 'none') {

    echo { 'unconfigured-daemons':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
