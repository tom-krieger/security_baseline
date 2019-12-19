# @summary A short summary of the purpose of this class
#
# A description of what this class does
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
# @param suid_expected
#    Array with expected suid programs.
#
# @example
#   class security_baseline::rules::common::sec_audit_suid_programs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::common::sec_audit_suid_programs (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
  Array $suid_expected = [],
) {
  if ($enforce) {
    if('security_baseline_suid_programs' in $facts) {
      $facts['security_baseline_suid_programs'].each |$suid| {
        unless($suid in $suid_expected) {
          echo { "unexpected-suid-program-${suid}":
            message  => "unexpected suid program ${suid}",
            loglevel => 'warning',
            withpath => false,
          }
        }
      }
    }
  } else {
    echo { 'suid-programs':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
