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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::common::sec_tmp_nosuid {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_tmp_nosuid (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    if (
      ($facts['security_baseline']['partitions']['tmp']['nosuid'] == false) and
      (has_key($facts['mountpoints'], '/tmp'))
    ) {
      security_baseline::set_mount_options { '/tmp-nosuid':
        mountpoint   => '/tmp',
        mountoptions => 'nosuid',
      }
    }
  } else {
    if $facts['security_baseline']['partitions']['tmp']['nosuid'] == false {
      echo { 'tmp-nosuid':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
