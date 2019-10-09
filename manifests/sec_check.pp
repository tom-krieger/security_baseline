# @summary
#    Check a security rule. 
#
# Check a security rule, enforce it or just monitor it and log into the Puppet log files.
#
# @param rulename
#    Name of the rule for loggting
#
# @param active
#    Sets a rule active or inactive. Inactive rules will not be used
#
# @param description
#    Information about the rule. Currently only for information.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param class 
#    Class implementing the rule. This might be a class with this module but can reference an external class as well. 
#    This makes this module highly generic.
#
# @param check
#    A hash describing the fact for the test and the desired value
# 
# @param message
#    Message to print into the log
#
# @param loglevel
#    Loglevel for the message
#
# @param config_data
#    Additional configuration data, especially if external security modules are used to provide configuration data
#    to those modules
#
# @example
#   security_baseline::sec_check { '1.1.2': 
#       rulename    => 'tmp_partition',
#       active      => true,
#       description => 'The /tmp directory ...',
#       enforce     => true,
#       class       => '::security_baseline::rules::sec_tmp_partition',
#       check       => {
#         fact_name  => 'tmp_partition',
#         fact_value => '/tmp',
#       },
#       message     => 'Not in compliance with rule 1.1.2. No seperate directory for /tmp.',
#       log_level   => 'warning',
#   }
define security_baseline::sec_check (
  String $rulename,
  String $description,
  Boolean $enforce,
  String $class,
  Hash $check,
  String $message             = '',
  String $log_level           = 'warning',
  Boolean $active             = true,
  Optional[Hash] $config_data = {},
) {

    if($active) {

      $logentry_default = {
        rulenr    => $title,
        rule      => $rulename,
        desc      => $description,
      }

      if($::security_baseline::debug) {
        echo{"Applying rule ${rulename}":
          loglevel => 'debug',
          withpath => false,
        }
      }

      $fact_name = $check['fact_name']
      if($fact_name != '') {
        $fact_value = $check['fact_value']
        $data_hash  = $facts[$check['fact_hash']]

        if(! $data_hash.empty()) {
          $current_value = dig($data_hash, *$fact_name)
        } else {
          $current_value = $facts[$fact_name]
        }

        if($current_value) {

          if($current_value.is_a(Array) and $fact_value.is_a(Array)) {
            
            unless(member($current_value, $fact_value)) {
              echo { "Fact ${fact_name} should have value '${fact_value}' but has current value '${current_value}'":
                loglevel => $loglevel,
                withpath => false,
              }

              $logentry_data = {
                level      => $log_level,
                msg       => $message,
                rulestate => 'not compliant',
              }
            }
          } else {
              if($current_value != $fact_value) {
              echo { "Fact ${fact_name} should have value '${fact_value}' but has current value '${current_value}'":
                loglevel => $loglevel,
                withpath => false,
              }

              $logentry_data = {
                level      => $log_level,
                msg       => $message,
                rulestate => 'not compliant',
              }

            } else {

              # fact contains expected value
              $logentry_data = {
                level     => 'ok',
                msg       => $message,
                rulestate => 'compliant',
              }
            }
          }
        } else {

          # if no current value is available assume test is compliant
          $logentry_data = {
            level     => 'ok',
            msg       => $message,
            rulestate => 'compliant',
          }

          if($fact_name.is_a(Array)) {
            $fact_key = join($fact_name, ' => ')
          } else {
            $fact_key = $fact_name
          }

          warning("No fact for ${fact_key} found")
        }

      } else {

        # if no fact name is available assume test is compliant
        $logentry_data = {
          level     => 'ok',
          msg       => $message,
          rulestate => 'compliant',
        }
      }

      # internal classes are supposed to start with ::security_baseline::rules
      # logging is done within this resource and no concat target is needed
      if($class =~ /^::security_baseline::rules::/) {

        $data = {
          'enforce'   => $enforce,
          'message'   => $message,
          'log_level' => $log_level,
        }

      } else {

        $data = {
          'enforce'   => $enforce,
          'message'   => $message,
          'log_level' => $log_level,
          'logfile'   => $::security_baseline::logfile,
        }

      }

      $logentry = $logentry_default + $logentry_data
      ::security_baseline::logging { $title:
        * => $logentry,
      }

      $merged_data = merge($data, $config_data)
      class { $class:
        * => $merged_data
      }

    } # rule active
}
