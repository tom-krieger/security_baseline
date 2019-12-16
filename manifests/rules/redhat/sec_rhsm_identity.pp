# @summary 
#    Ensure Red Hat Subscription Manager connection is configured (Not Scored)
#
# Systems need to be registered with the Red Hat Subscription Manager (RHSM) to receive patch updates. 
# This is usually configured during initial installation.
#
# Rationale:
# It is important to register with the Red Hat Subscription Manager to make sure that patches are updated on a regular 
# basis. This helps to reduce the exposure time as new vulnerabilities are discovered.
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
#   class security_baseline::rules::redhat::sec_rhsm_identity {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_rhsm_identity (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  unless($facts['rhsm_identity']) {
    echo { 'rhsm-identity':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
