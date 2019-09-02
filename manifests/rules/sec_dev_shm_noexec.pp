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
# @param loglevel
#    The loglevel for the above message
#
# @example
#   class security_baseline::rules::sec_dev_shm_noexec {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_dev_shm_noexec (
  $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {

    if $::dev_shm_partition {

      if $::dev_shm_noexec == false {
        echo { 'dev-shm-noexec':
          message  => $message,
          loglevel => $loglevel,
          withpath => false,
        }
      }
    }
  }
}
