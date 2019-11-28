# @summary 
#    Ensure separate partition exists for /var (Scored)
#
# The /var directory is used by daemons and other system services to temporarily store dynamic data. 
# Some directories created by these processes may be world-writable.
#
# Rationale:
# Since the /var directory may contain world-writable files and directories, there is a risk of 
# resource exhaustion if it is not bound to a separate partition.
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
#   class security_baseline::rules::sec_var_partition {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_var_partition (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {

  if($enforce) {
    if defined($facts['security_baseline']['partitions']['var']['partition']) and
      ($facts['security_baseline']['partitions']['var']['partition'] == undef) {

      echo { 'var-partition':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }

}
