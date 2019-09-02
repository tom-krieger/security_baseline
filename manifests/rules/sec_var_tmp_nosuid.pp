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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_var_tmp_nosuid {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_var_tmp_nosuid (
  $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {

    if $::var_partition {

      if $::var_tmp_noexec == false {
        echo { 'var-tmp-noexec':
          message  => $message,
          loglevel => $loglevel,
          withpath => false,
        }
      }
    }
  }
}
