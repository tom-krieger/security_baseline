# @summary 
#    Ensure mounting of FAT filesystems is disabled (Scored)
#
# The FAT filesystem format is primarily used on older windows systems and portable 
# USB drives or flash modules. It comes in three types FAT12 , FAT16 , and FAT32 all 
# of which are supported by the vfat kernel module.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of 
# the system. If this filesystem type is not needed, disable it.
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
#   class security_baseline::rules::sec_vfat {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_vfat (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {
    kmod::install { 'vfat':
      command => '/bin/true',
    }
  }
}
