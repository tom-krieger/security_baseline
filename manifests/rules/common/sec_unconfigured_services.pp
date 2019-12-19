# @summary 
#    Ensure no unconfined services exist (Scored)
#
# Unconfined processes run in unconfined domains
#
# Rationale:
# For unconfined processes, SELinux policy rules are applied, but policy rules exist that allow processes running 
# in unconfined domains almost all access. Processes running in unconfined domains fall back to using DAC rules 
# exclusively. If an unconfined process is compromised, SELinux does not prevent an attacker from gaining access 
# to system resources and data, but of course, DAC rules are still used. SELinux is a security enhancement on top 
# of DAC rules – it does not replace them
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
#   class security_baseline::rules::common::sec_unconfigured_services {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_unconfigured_services (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['unconfigured_services'] != 'none') {
    echo { 'unconfigured-services':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
