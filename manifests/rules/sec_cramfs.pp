# @summary 
#    Ensure mounting of cramfs filesystems is disabled (Scored)
#
# The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small 
# footprint systems. A cramfs image can be used without having to first decompress the image.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of the server. 
# If this filesystem type is not needed, disable it.
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
#   class security_baseline::rules::sec_cramfs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_cramfs (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {
    kmod::install { 'cframfs':
      command => '/bin/true',
    }
  } else {
    if($facts['security_baseline']['kernel_modules']['cramfs']) {
      echo { 'cramfs':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
