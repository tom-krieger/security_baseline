# @summary 
#    Ensure nosuid option set on /tmp partition (Scored)    
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files.
#
# Rationale:
# Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure 
# that users cannot create setuid files in /tmp .
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
#   class security_baseline::rules::sec_tmp_nosuid {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_tmp_nosuid (
  $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {

    if $::tmp_partition {

      if $::tmp_nosuid == false {
        echo { 'tmp-nosuid':
          message  => $message,
          loglevel => $loglevel,
        }
      }
    }
  }
}
