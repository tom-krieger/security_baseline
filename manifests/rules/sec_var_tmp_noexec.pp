# @summary 
#    Ensure noexec option set on /var/tmp partition (Scored)
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries.
#
# Rationale:
# Since the /var/tmp filesystem is only intended for temporary file storage, set this option to 
# ensure that users cannot run executable binaries from /var/tmp .
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
#   class security_baseline::rules::sec_var_tmp_noexec {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_var_tmp_noexec (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {

    if $::var_tmp_partition {

      if $::var_tmp_noexec == false {
        echo { 'var-tmp-noexec':
          message   => $message,
          log_level => $log_level,
          withpath  => false,
        }
      }
    }
  }
}
