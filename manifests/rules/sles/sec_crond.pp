# @summary 
#    Ensure cron daemon is enabled (Scored)
#
# The cron daemon is used to execute batch jobs on the system.
#
# Rationale:
# While there may not be user jobs that need to be run on the system, the system does have maintenance 
# jobs that may include security monitoring that have to run, and cron is used to execute them.
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
#   class security_baseline::rules::sles::sec_crond {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_crond (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    ensure_resource('service', ['cron'], {
      ensure => 'running',
      enable => true
    })

  } else {

    if($facts['security_baseline']['services_enabled']['srv_crond'] != 'enabled') {
      echo { 'crond':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
