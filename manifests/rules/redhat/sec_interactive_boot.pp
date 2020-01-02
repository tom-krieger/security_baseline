# @summary 
#    Ensure interactive boot is not enabled (Scored)
#
# Interactive boot allows console users to interactively select which services start on boot.
# The PROMPT option provides console users the ability to interactively boot the system and select 
# which services to start on boot.
#
# Rationale:
# Turn off the PROMPT option on the console to prevent console users from potentially overriding 
# established security settings.
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
#   class security_baseline::rules::redhat::sec_interactive_boot {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_interactive_boot (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'interactive_boot':
      path               => '/etc/sysconfig/init',
      line               => 'PROMPT=no',
      match              => '^PROMPT=',
      append_on_no_match => true,
    }
  } else {
    if($facts['security_baseline']['interactive_boot']['status'] == false) {
      echo { 'interactive_boot':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
