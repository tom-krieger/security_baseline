# @summary 
#    Write concat fragments to a logfile
#
# Logging resource to write parts of the log.
#
# @param rulenr
#     Number of the rule to be written into the log
#
# @param rule
#    A name for the rule to be written into the logfile
#
# @param desc
#    Description of the rule
#
# @param log_level
#    Log level for the message in the log
#
# @param msg
#    The log message
#
# @param rulestate 
#    Status of the rule, e. g. compliant or fail
#
# @param level
#    The level from the CIS benchmark
#
# @param scored
#    Flag if rule is scored
#
# @param reporting_type
#    Type of report.
#
# @example
#   security_baseline::logging { '1.1.1.1': 
#     rulenr    => '1.1.1.1',
#     rule      => 'Test Rule',
#     desc      => 'What ever description you like',
#     level     => 'warning',
#     msg       => 'A suitable message',
#     rulestate => 'fail'
#   }
define security_baseline::logging (
  $rulenr,
  $rule,
  $desc,
  $log_level,
  $msg,
  $rulestate,
  $level,
  $scored,
  Enum['fact', 'csv_file', 'none'] $reporting_type = 'fact',
) {
  if($reporting_type == 'fact') {
      concat::fragment { $rulenr:
        content => epp('security_baseline/logentry.epp', {
          'rulenr'    => $rulenr,
          'rule'      => $rule,
          'desc'      => $desc,
          'msg'       => $msg,
          'loglevel'  => $log_level,
          'rulestate' => $rulestate,
          'level'     => $level,
          'scored'    => $scored,
        }),
        target  => $::security_baseline::logfile,
    }
  } elsif ($reporting_type == 'csv_file') {
    concat::fragment { $rulenr:
        content => epp('security_baseline/csv_file_entry.epp', {
          'rulenr'    => $rulenr,
          'rule'      => $rule,
          'desc'      => $desc,
          'msg'       => $msg,
          'loglevel'  => $log_level,
          'rulestate' => $rulestate,
          'level'     => $level,
          'scored'    => $scored,
        }),
        target  => $::security_baseline::logfile,
    }
  }
}
