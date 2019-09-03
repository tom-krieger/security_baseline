# @summary A short summary of the purpose of this defined type.
#
# A description of what this defined type does
#
# @example
#   security_baseline::logging { 'namevar': }
define security_baseline::logging (
  $rulenr,
  $rule,
  $desc,
  $level,
  $msg,
  $rulestate
) {
  concat::fragment { $rulenr:
    content => epp('security_baseline/logentry.epp', {
      'rulenr'    => $rulenr,
      'rule'      => $rule,
      'desc'      => $desc,
      'msg'       => $msg,
      'level'     => $level,
      'rulestate' => $rulestate,
    }),
    target  => $::security_baseline::logfile,
  }
}
