# @summary 
#    Ensure mounting of hfs filesystems is disabled (Scored)
#
# The hfs filesystem type is a hierarchical filesystem that allows you to mount Mac OS filesystems.
#
# Rationale:
# Removing support for unneeded filesystem types reduces the local attack surface of the system. 
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
#   class security_baseline::rules::common::sec_hfs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_hfs (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {
    kmod::install { 'hfs':
      command => '/bin/true',
    }
  } else {
    if($facts['security_baseline']['kernel_modules']['hfs']) {
      echo { 'hfs':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
