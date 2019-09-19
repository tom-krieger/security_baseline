# @summary 
#    Ensure updates, patches, and additional security software are installed (Scored)
#
# Periodically patches are released for included software either due to security flaws or to include 
# additional functionality.
#
# Rationale:
# Newer patches may contain security enhancements that would not be available through the latest full 
# update. As a result, it is recommended that the latest software patches be used to take advantage of 
# the latest functionality. As with any software installation, organizations need to determine if a given 
# update meets their requirements and verify the compatibility and supportability of any additional software 
# against the update revision that is selected.
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
#   class security_baseline::rules::sec_security_patches {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_security_patches (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    if($facts['security_baseline']['security_patches']) {

      echo { 'security-patches':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
