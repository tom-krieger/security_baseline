# @summary 
#    Ensure mounting of udf filesystems is disabled (Scored)
#
# The udf filesystem type is the universal disk format used to implement ISO/IEC 
# 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data 
# storage on a broad range of media. This filesystem type is necessary to support 
# writing DVDs and newer optical disc formats.
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
#   class security_baseline::rules::common::sec_udf {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_udf (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if $enforce {
    kmod::install { 'udf':
      command => '/bin/true',
    }
  } else {
    if($facts['security_baseline']['kernel_modules']['udf']) {
      echo { 'udf':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
