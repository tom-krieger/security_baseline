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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_var_partition {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_var_partition (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {

  if($enforce) {
    if $::var_partition == undef {

      echo { 'var-partition':
        message  => $message,
        loglevel => $loglevel,
        }
      }
  }

}
