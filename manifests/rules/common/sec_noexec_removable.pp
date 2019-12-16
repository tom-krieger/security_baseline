# @summary 
#    Ensure noexec option set on removable media partitions (Not Scored)
#
# The noexec mount option specifies that the filesystem cannot contain executable binaries. 
#
# Rationale:
# Setting this option on a file system prevents users from executing programs from the removable media. This 
# deters users from being able to introduce potentially malicious software on the system.
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
#   class security_baseline::rules::common::sec_noexec_removable {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_noexec_removable (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  $facts['mountpoints'].each | Tuple $mntpt | {
    if ($mntpt[0] =~ /cdrom/) or ($mntpt[0] =~ /floppy/) {
      if(!('noexec' in $facts['mountpoints'][$mntpt[0]]['options'])) {
        echo { "removable-noexec ${mntpt[0]}":
          message  => "${message} ${mntpt[0]}",
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
