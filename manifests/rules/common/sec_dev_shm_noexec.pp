# @summary 
#    Ensure noexec option set on /dev/shm partition (Scored)
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries.
#
# Rationale:
# Setting this option on a file system prevents users from executing programs from shared memory. 
# This deters users from introducing potentially malicious software on the system.
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
#   class security_baseline::rules::common::sec_dev_shm_noexec {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_dev_shm_noexec (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if $enforce {
    security_baseline::mount_options { '/dev/shm-noexec':
      mountpoint   => '/dev/shm',
      mountoptions => 'noexec',
    }
  } else {
    if $facts['security_baseline']['partitions']['shm']['nosuid'] == false {
      echo { 'dev-shm-noexec':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
