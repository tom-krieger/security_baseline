# @summary 
#    Ensure time synchronization is in use (Not Scored)
#
# System time should be synchronized between all systems in an environment. This is typically done by establishing an 
# authoritative time server or set of servers and having all systems synchronize their clocks to them.
#
# Rationale:
# Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log 
# files have consistent time records across the enterprise, which aids in forensic investigations.
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
#   class security_baseline::rules::common::sec_ntp_usage {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_ntp_usage (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['ntp_use'] != 'used') {
    echo { 'ntp-usage':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
