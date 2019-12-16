# @summary 
#    Ensure nodev option set on removable media partitions (Not Scored)
#
# The nodev mount option specifies that the filesystem cannot contain special devices. 
#
# Rationale:
# Removable media containing character and block special devices could be used to circumvent security controls 
# by allowing non-root users to access sensitive device files such as /dev/kmem or the raw disk partitions.
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
#   class security_baseline::rules::common::sec_nodev_removable {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_nodev_removable (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  $facts['mountpoints'].each | Tuple $mntpt | {
    if ($mntpt[0] =~ /cdrom/) or ($mntpt[0] =~ /floppy/) {
      if(!('nodev' in $facts['mountpoints'][$mntpt[0]]['options'])) {
        echo { "removable-nodev ${mntpt[0]}":
          message  => "${message} ${mntpt[0]}",
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
