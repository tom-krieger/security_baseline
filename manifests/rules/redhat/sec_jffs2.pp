# @summary 
#    Ensure mounting of jffs2 filesystems is disabled (Scored)
#
# The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured 
# filesystem used in flash memory devices.
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
#   class security_baseline::rules::redhat::sec_jffs2 {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_jffs2 (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {

  if $enforce {
    kmod::install { 'jffs2':
      command => '/bin/true',
    }
  } else {
    if($facts['security_baseline']['kernel_modules']['jffs2']) {
      echo { 'jffs2':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
