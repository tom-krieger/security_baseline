# @summary 
#    Ensure mounting of freevxfs filesystems is disabled (Scored)
#
# The freevxfs filesystem type is a free version of the Veritas type filesystem. This is 
# the primary filesystem type for HP-UX operating systems.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of the 
# system. If this filesystem type is not needed, disable it.
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
#   class security_baseline::rules::common::sec_freevxfs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_freevxfs (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {
    kmod::install { 'freevxfs':
      command => '/bin/true',
    }
  } else {
    if($facts['security_baseline']['kernel_modules']['freevxfs']) {
      echo { 'freevxfs':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
