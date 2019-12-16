# @summary 
#    Ensure nosuid option set on removable media partitions (Not Scored)
#
# The nosuid mount option specifies that the filesystem cannot contain setuid files. 
#
# Rationale:
# Setting this option on a file system prevents users from introducing privileged programs onto the 
# system and allowing non-root users to execute them.
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
#   class security_baseline::rules::common::sec_nosuid_removable {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_nosuid_removable (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  $facts['mountpoints'].each | Tuple $mntpt | {
    if ($mntpt[0] =~ /cdrom/) or ($mntpt[0] =~ /floppy/) {
      if(!('nosuid' in $facts['mountpoints'][$mntpt[0]]['options'])) {
        echo { "removable-nosuid ${mntpt[0]}":
          message  => "${message} ${mntpt[0]}",
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
