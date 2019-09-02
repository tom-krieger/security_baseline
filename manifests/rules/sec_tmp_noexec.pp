# @summary 
#    Ensure noexec option set on /tmp partition (Scored)
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries.
#
# Rationale:
# Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure 
# that users cannot run executable binaries from /tmp .
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
#   class security_baseline::rules::sec_tmp_noexec {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_tmp_noexec (
  $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {

    if $::tmp_partition {

      if $::tmp_noexec == false {
        echo { 'tmp-noexec':
          message  => $message,
          loglevel => $loglevel,
        }
      }
    }
  }
}
