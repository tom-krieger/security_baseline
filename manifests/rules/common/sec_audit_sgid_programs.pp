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
# @param sgid_expected
#    Array with expected sgid programs
#
# @example
#   class security_baseline::rules::common::sec_audit_sgid_programs {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::common::sec_audit_sgid_programs (
  Boolean $enforce     = true,
  String $message      = '',
  String $log_level    = '',
  Array $sgid_expected = [],
) {
  if ($enforce) {
    if('security_baseline_sgid_programs' in $facts) {
      $facts['security_baseline_sgid_programs'].each |$sgid| {
        unless($sgid in $sgid_expected) {
          echo { "unexpected-sgid-program-${sgid}":
            message  => "unexpected sgid program ${sgid}",
            loglevel => 'warning',
            withpath => false,
          }
        }
      }
    }
  } else {
    echo { 'sgid-programs':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
