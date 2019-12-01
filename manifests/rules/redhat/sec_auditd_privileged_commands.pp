# @summary 
#    Ensure use of privileged commands is collected (Scored)
#
# Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to 
# determine if unprivileged users are running these commands.
#
# Rationale:
# Execution of privileged commands by non-privileged users could be an indication of someone trying 
# to gain unauthorized access to the system.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param message
#    Message to print into the log
#
# @param log_level
#    Loglevel for the message
#
# @param level
#    Profile level
#
# @param scored
#    Indicates if a rule is scored or not
#
# @example
#   class { 'security_baseline::rules::redhat::sec_auditd_privileged_commands':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_auditd_privileged_commands (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {
    $facts['security_baseline']['auditd']['priv-cmds-list'].each |$part, $rules| {
      $rules.each |$rule| {
        file_line { $rule:
          ensure => present,
          path   => $security_baseline::auditd_rules_file,
          line   => $rule,
        }
      }
    }
  } else {
    if($facts['security_baseline']['auditd']['priv-cmds'] == false) {
      echo { 'auditd-priv-cmds':
        message  => 'Auditd has no rule to collect use of privileged commands.',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
