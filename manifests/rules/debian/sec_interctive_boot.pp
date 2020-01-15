# @summary 
#    Ensure interactive boot is not enabled (Not Scored)
#
# Interactive boot allows console users to interactively select which services start on boot. Not all 
# distributions support this capability.
# The PROMPT_FOR_CONFIRM option provides console users the ability to interactively boot the system 
# and select which services to start on boot .
#
# Rationale:
# Turn off the PROMPT_FOR_CONFIRM option on the console to prevent console users from potentially 
# overriding established security settings.
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
#   class security_baseline::rules::debian::sec_interctive_boot {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_interctive_boot (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    if($facts['security_baseline']['interactive_boot'] != 'n/a') {
      file_line { 'interactive-boot':
        ensure             => 'present',
        path               => '/etc/sysconfig/boot',
        line               => 'PROMPT_FOR_CONFIRM="no"',
        match              => '^PROMPT_FOR_CONFIRM=',
        append_on_no_match => true,
      }
    }
  } else {
    if(
      ($facts['security_baseline']['interactive_boot'] != 'no') and
      ($facts['security_baseline']['interactive_boot'] != 'n/a')
    ) {
      echo { 'interactive_boot':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
