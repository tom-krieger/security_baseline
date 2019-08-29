# @summary 
#    Ensure mounting of squashfs filesystems is disabled (Scored)
#
# The squashfs filesystem type is a compressed read-only Linux filesystem embedded in 
# small footprint systems (similar to cramfs ). A squashfs image can be used without 
# having to first decompress the image.
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
#   class security_baseline::rules::sec_squashfs {
#       enforce => true,
#       message => 'Test',
#       loglevel => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_squashfs (
  Boolean $enforce = true,
  String $message = '',
  String $loglevel = ''
) {
  if $enforce {
    kmod::install { 'squashfs':
      command => '/bin/true',
    }
  }
}
