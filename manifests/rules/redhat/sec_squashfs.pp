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
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::redhat::sec_squashfs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_squashfs (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {
    kmod::install { 'squashfs':
      command => '/bin/true',
    }
  } else {
    if($facts['security_baseline']['kernel_modules']['squashfs']) {
      echo { 'squashfs':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
