# @summary 
#    Ensure separate partition exists for /var/log (Scored)
#
# The /var/log directory is used by system services to store log data.
#
# Rationale:
# There are two important reasons to ensure that system logs are stored on a separate partition: 
# protection against resource exhaustion (since logs can grow quite large) and protection of audit data.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_var_log_partition {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_var_log_partition (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {

  if($enforce) {
    if $::var_log_partition == undef {

      echo { 'var-log-partition':
        message  => $message,
        loglevel => $loglevel,
        withpath => false,
      }
    }
  }

}
