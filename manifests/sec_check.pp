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
# @param level
#    Profile level
#
# @param scored
#    Indicates if a ruile is scored or not
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
# @param log_level
#    Loglevel for the message
#
# @param reboot
#    If set to true and global reboot is allowed a class firing with this flag
#    will trigger a reboot after catalog apply has finished
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
#
define security_baseline::sec_check (
  String $rulename,
  String $description,
  Boolean $enforce,
  String $class,
  Hash $check,
  String $message             = '',
  String $log_level           = 'warning',
  Boolean $active             = true,
  Integer $level              = 1,
  Boolean $scored             = true,
  Boolean $reboot             = false,
  Optional[Hash] $config_data = {},
) {

    $reporting_type = $::security_baseline::reporting_type

    if $::security_baseline::dry_run {
      $real_enforce = false
    } else {
      $real_enforce = $enforce
    }

    if($active) and (has_key($facts, 'security_baseline')) {

      $logentry_default = {
        rulenr         => $title,
        rule           => $rulename,
        desc           => $description,
        level          => $level,
        scored         => $scored,
        reporting_type => $reporting_type,
      }

      if($::security_baseline::debug) {
        echo { "Applying rule ${rulename}":
          loglevel => 'debug',
          withpath => false,
        }
      }

      $fact_name = $check['fact_name']
      unless (empty($fact_name)) {
        $fact_value = $check['fact_value']
        $data_hash  = $facts[$check['fact_hash']]

        if($::security_baseline::debug) {
          echo { "fact name: ${fact_name}":
            loglevel => 'info',
            withpath => false,
          }
        }

        unless(empty($data_hash)) {
          $current_value = dig($data_hash, *$fact_name)
        } else {
          $current_value = $facts[$fact_name]
        }

        if($::security_baseline::debug) {
          echo { "current value ${fact_name} -> ${current_value}":
            loglevel => 'info',
            withpath => false,
          }
        }

        unless($current_value == undef) {

          if($current_value.is_a(Array) and $fact_value.is_a(Array)) {

            if(member($current_value, $fact_value)) {
              # fact contains expected value
              $logentry_data = {
                log_level => 'ok',
                msg       => $message,
                rulestate => 'compliant',
              }
            } else {
              if($::security_baseline::debug) {
                echo { "Rule ${title}. Fact ${fact_name} should have value '${fact_value}' but has current value '${current_value}'":
                  loglevel => $log_level,
                  withpath => false,
                }
              }

              $logentry_data = {
                log_level => $log_level,
                msg       => $message,
                rulestate => 'not compliant',
              }
            }
          } else {
            if($current_value != $fact_value) {
              if($::security_baseline::debug) {
                echo { "Rule ${title}. Fact ${fact_name} should have value '${fact_value}' but has current value '${current_value}'":
                  loglevel => $log_level,
                  withpath => false,
                }
              }

              $logentry_data = {
                log_level => $log_level,
                msg       => $message,
                rulestate => 'not compliant',
              }
            } else {

              # fact contains expected value
              $logentry_data = {
                log_level => 'ok',
                msg       => $message,
                rulestate => 'compliant',
              }
            }
          }
        } else {

          # if no current value is available assume test is compliant
          $logentry_data = {
            log_level => 'ok',
            msg       => $message,
            rulestate => 'compliant (no value)',
          }

          if($fact_name.is_a(Array)) {
            $fact_key = join($fact_name, ' => ')
          } else {
            $fact_key = $fact_name
          }

          echo { "No fact for ${fact_key} found":
            loglevel => 'warning',
            withpath => false,
          }
        }

      } else {

        # if no fact name is available assume test is compliant
        $logentry_data = {
          log_level => 'ok',
          msg       => $message,
          rulestate => 'compliant (no value)',
        }
      }

      # internal classes are supposed to start with ::security_baseline::rules
      # logging is done within this resource and no concat target is needed
      if($class =~ /^::security_baseline::rules::/) or ($class =~ /^security_baseline::rules::/) {

        $data = {
          'enforce'   => $real_enforce,
          'message'   => $message,
          'log_level' => $log_level,
        }

      } else {

        $data = {
          'enforce'   => $real_enforce,
          'message'   => $message,
          'log_level' => $log_level,
          'logfile'   => $::security_baseline::logfile,
        }

      }

      if ($::security_baseline::reports == 'both' or $::security_baseline::reports == 'details') {
        $logentry = $logentry_default + $logentry_data
        ::security_baseline::logging { $title:
          * => $logentry,
        }
      }

      $merged_data = merge($data, $config_data)
      class { $class:
        * => $merged_data
      }

    }
}
