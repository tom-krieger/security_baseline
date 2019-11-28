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
#   class security_baseline::rules::redhat::sec_dev_shm_noexec {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_dev_shm_noexec (
  $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {

    if $::dev_shm_partition {

      if $facts['security_baseline']['partitions']['shm']['noexec'] == false {
        echo { 'dev-shm-noexec':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
