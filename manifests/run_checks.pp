# @summary 
#    Run security checks
# 
# Run the security checks
#
# @param rules
#    Hash with all rules to check
#
# @example
#   class { 'security_baseline::run_checks':
#     rules => $rules,
#   }
# 
# @api private
class security_baseline::run_checks (
  Hash $rules = {},
){
  $rules.each |$rule_title, $rule_data| {
    ::security_baseline::sec_check { $rule_title:
      * => $rule_data,
    }
  }

  # create_resources('::security_baseline::sec_check', $rules)
}
