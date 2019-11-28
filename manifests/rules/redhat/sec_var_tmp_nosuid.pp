# @summary 
#    Ensure nosuid option set on /var/tmp partition (Scored)
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files.
#
# Rationale:
# Since the /var/tmp filesystem is only intended for temporary file storage, set this option to ensure 
# that users cannot create setuid files in /var/tmp .
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
#   class security_baseline::rules::redhat::sec_var_tmp_nosuid {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_var_tmp_nosuid (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {

    if (has_key($facts, 'security_baseline')) and
      defined($facts['security_baseline']['partitions']['var_tmp']['partition']) {

      if $facts['security_baseline']['partitions']['var_tmp']['nosuid'] == false {
        echo { 'var-tmp-noexec':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
